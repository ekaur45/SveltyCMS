import { error, fail, redirect, type Cookies } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

// Auth
import { auth, googleAuth, initializationPromise } from '@api/databases/db';
import { google } from 'googleapis';
import type { User } from '@src/auth/types';

// Store
import { systemLanguage } from '@stores/store';
import { get } from 'svelte/store';
import { privateEnv } from '@root/config/private';
import { message, superValidate } from 'sveltekit-superforms/server';
import { zod } from 'sveltekit-superforms/adapters';
import { forgotFormSchema, loginFormSchema, resetFormSchema, signUpFormSchema, signUpOAuthFormSchema } from '@src/utils/formSchemas';
import { publicEnv } from '@root/config/public';
import { dev } from '$app/environment';

export const load: PageServerLoad = async ({ url, cookies, fetch }) => {
	await initializationPromise;
	const code = url.searchParams.get('code');
	console.log('Authorization code:', code);

	const result: Result = {
		errors: [],
		success: true,
		message: '',
		data: {
			needSignIn: false
		}
	};

	if (privateEnv.USE_GOOGLE_OAUTH&&!code) {
		console.error('Authorization code is missing');
		throw redirect(302, '/login');
	}

	if (!auth) {
		console.error('Authentication system is not initialized');
		throw new Error('Internal Server Error');
	}

	if(privateEnv.USE_GOOGLE_OAUTH){
		try {
			const { tokens } = await googleAuth.getToken(code);
			googleAuth.setCredentials(tokens);
			const oauth2 = google.oauth2({ auth: googleAuth, version: 'v2' });
	
			const { data: googleUser } = await oauth2.userinfo.get();
			console.log('Google user information:', googleUser);
	
			const getUser = async (): Promise<[User | null, boolean]> => {
				const existingUser = await auth.checkUser({ email: googleUser.email });
				if (existingUser) return [existingUser, false];
	
				// Ensure Google user email exists
				if (!googleUser.email) {
					throw new Error('Google did not return an email address.');
				}
				const username = googleUser.name ?? '';
	
				const isFirst = (await auth.getUserCount()) === 0;
	
				if (isFirst) {
					const user = await auth.createUser({
						email: googleUser.email,
						username,
						role: 'admin',
						blocked: false
					});
	
					await fetch('/api/sendMail', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json'
						},
						body: JSON.stringify({
							email: googleUser.email,
							subject: `New registration ${googleUser.name}`,
							message: `New registration ${googleUser.name}`,
							templateName: 'welcomeUser',
							lang: get(systemLanguage),
							props: {
								username: googleUser.name,
								email: googleUser.email
							}
						})
					});
	
					return [user, false];
				} else {
					return [null, true];
				}
			};
	
			const [user, needSignIn] = await getUser();
	
			if (!needSignIn) {
				if (!user) {
					console.error('User not found after getting user information.');
					throw new Error('User not found.');
				}
				if ((user as any).blocked) {
					console.warn('User is blocked.');
					return { status: false, message: 'User is blocked' };
				}
	
				// Create User Session
				const session = await auth.createSession({ userId: user._id.toString(), expires: 3600000 });
				const sessionCookie = auth.createSessionCookie(session);
				cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
				await auth.updateUserAttributes(user._id.toString(), { lastAuthMethod: 'google' });
			}
			result.data = { needSignIn };
		} catch (e) {
			console.error('Error during login process:', e);
			//throw redirect(302, '/login');
		}
	}
// Default email/password authentication flow
if (!auth) {
	throw new Error('Internal Server Error');
}

// Check if first user exists
const firstUserExists = (await auth.getUserCount()) !== 0;

// SignIn
const loginForm = await superValidate(zod(loginFormSchema));
const forgotForm = await superValidate(zod(forgotFormSchema));
const resetForm = await superValidate(zod(resetFormSchema));
const signUpForm = firstUserExists
	? await superValidate(zod(signUpFormSchema.innerType().omit({ token: true })))
	: await superValidate(zod(signUpFormSchema));

// Always return Data & all Forms in load and form actions.
return {
	firstUserExists,
	loginForm,
	forgotForm,
	resetForm,
	signUpForm
};
	//if (!result.data.needSignIn) throw redirect(303, '/');
	//return result;
};

export const actions: Actions = {
	// Handling the Sign-Up form submission and user creation
	signUp: async (event) => {
		if (!auth) {
			console.error('Authentication system is not initialized');
			throw error(500, 'Internal Server Error');
		}

		console.debug('action signUp');
		const isFirst = (await auth.getUserCount()) == 0;
		const signUpForm = await superValidate(event, zod(signUpFormSchema));

		// Validate
		const username = signUpForm.data.username;
		const email = signUpForm.data.email.toLowerCase();
		const password = signUpForm.data.password;
		const token = signUpForm.data.token;

		const user = await auth.checkUser({ email });

		let resp: { status: boolean; message?: string } = { status: false };

		if (user && user.is_registered) {
			// Finished account exists
			return { form: signUpFormSchema, message: 'This email is already registered' };
		} else if (isFirst) {
			// No account exists signUp for admin
			resp = await FirstUsersignUp(username, email, password, event.cookies);
		} else if (user && user.is_registered == false) {
			// Unfinished account exists
			resp = await finishRegistration(username, email, password, token, event.cookies);
		} else if (!user && !isFirst) {
			resp = { status: false, message: 'This user was not defined by admin' };
		}

		if (resp.status) {
			console.debug(`resp: ${JSON.stringify(resp)}`);

			// Send welcome email
			await event.fetch('/api/sendMail', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					email,
					subject: `New registration for ${username}`,
					message: `Welcome ${username} to ${publicEnv.SITE_NAME}`,
					templateName: 'welcomeUser',

					props: {
						username,
						email
					}
				})
			});

			// Return message if form is submitted successfully
			message(signUpForm, 'SignUp User form submitted');
			throw redirect(303, '/');
		} else {
			console.warn(`Sign-up failed: ${resp.message}`);
			return { form: signUpForm, message: resp.message || 'Unknown error' };
		}
	},

	// OAuth Sign-Up
	OAuth: async (event) => {
		console.debug('OAuth action called');

		const signUpOAuthForm = await superValidate(event, zod(signUpOAuthFormSchema));
		console.debug(`signUpOAuthForm: ${JSON.stringify(signUpOAuthForm)}`);

		const lang = signUpOAuthForm.data.lang;
		console.debug(`lang: ${lang}`);

		const scopes = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email', 'openid'];

		try {
			const redirectUrl = googleAuth!.generateAuthUrl({
				access_type: 'offline',
				scope: scopes,
				redirect_uri: 'http://localhost:5173/login/oauth' // Make sure this matches your Google OAuth settings
			});
			console.debug(`Generated redirect URL: ${redirectUrl}`);

			if (!redirectUrl) {
				console.error('Error during OAuth callback: Redirect URL not generated');
				throw error(500, 'Failed to generate redirect URL.');
			} else {
				console.debug(`Redirecting to: ${redirectUrl}`);
				throw redirect(307, redirectUrl);
			}
		} catch (err) {
			console.error(`Error in OAuth action: ${err}`);
			throw error(500, 'An error occurred during OAuth initialization');
		}
	},

	// Function for handling the SignIn form submission and user authentication
	signIn: async (event) => {
		const signInForm = await superValidate(event, zod(loginFormSchema));

		// Validate
		if (!signInForm.valid) return fail(400, { signInForm });

		const email = signInForm.data.email.toLowerCase();
		const password = signInForm.data.password;
		const isToken = signInForm.data.isToken;

		const resp = await signIn(email, password, isToken, event.cookies);

		if (resp && resp.status) {
			// Return message if form is submitted successfully
			message(signInForm, 'SignIn form submitted');
			throw redirect(303, '/');
		} else {
			// Handle the case when resp is undefined or when status is false
			const errorMessage = resp?.message || 'An error occurred during sign-in.';
			console.warn(`Sign-in failed: ${errorMessage}`);
			return { form: signInForm, message: errorMessage };
		}
	},

	// Function for handling the Forgotten Password
	forgotPW: async (event) => {
		const pwforgottenForm = await superValidate(event, zod(forgotFormSchema));
		console.debug(`pwforgottenForm: ${JSON.stringify(pwforgottenForm)}`);

		// Validate
		let resp: { status: boolean; message?: string } = { status: false };
		const email = pwforgottenForm.data.email.toLowerCase();
		const checkMail = await forgotPWCheck(email);

		if (email && checkMail.success) {
			// Email format is valid and email exists in DB
			resp = { status: true, message: checkMail.message };
		} else if (email && !checkMail.success) {
			// Email format is valid but email doesn't exist in DB
			resp = { status: false, message: checkMail.message };
		} else if (!email && !checkMail) {
			// Email format invalid and email doesn't exist in DB
			resp = { status: false, message: 'Invalid Email' };
		}

		if (resp.status) {
			// Get the token from the checkMail result
			const token = checkMail.token;
			const expiresIn = checkMail.expiresIn;
			// Define token resetLink
			const baseUrl = dev ? publicEnv.HOST_DEV : publicEnv.HOST_PROD;
			const resetLink = `${baseUrl}/login?token=${token}&email=${email}`;
			console.debug(`resetLink: ${resetLink}`);

			// Send welcome email
			await event.fetch('/api/sendMail', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				},
				body: JSON.stringify({
					email,
					subject: 'Forgotten Password',
					message: 'Forgotten Password',
					templateName: 'forgottenPassword',
					props: {
						email,
						token,
						expiresIn,
						resetLink
					}
				})
			});

			// Return message if form is submitted successfully
			message(pwforgottenForm, 'SignIn Forgotten form submitted');
			return { form: pwforgottenForm, token, email };
		} else {
			console.warn(`Forgotten password failed: ${resp.message}`);
			return { form: pwforgottenForm, status: checkMail.success, message: resp.message || 'Unknown error' };
		}
	},

	// Function for handling the RESET
	resetPW: async (event) => {
		console.debug('resetPW');
		const pwresetForm = await superValidate(event, zod(resetFormSchema));

		// Validate
		const password = pwresetForm.data.password;
		const token = pwresetForm.data.token;
		const email = pwresetForm.data.email;

		// Define expiresIn
		const expiresIn = 1 * 60 * 60; // expiration in 1 hours

		const resp = await resetPWCheck(password, token, email, expiresIn);
		console.debug(`resetPW resp: ${JSON.stringify(resp)}`);

		if (resp.status) {
			// Return message if form is submitted successfully
			message(pwresetForm, 'SignIn Reset form submitted');
			throw redirect(303, '/login');
		} else {
			console.warn(`Password reset failed: ${resp.message}`);
			return { form: pwresetForm, message: resp.message };
		}
	}
};
async function signIn(
	email: string,
	password: string,
	isToken: boolean,
	cookies: Cookies
): Promise<{ status: true } | { status: false; message: string }> {
	console.debug(`signIn called with email: ${email}, password: ${password}, isToken: ${isToken}`);

	if (!isToken) {
		if (!auth) {
			console.error('Authentication system is not initialized');
			throw error(500, 'Internal Server Error');
		}

		const user = await auth.login(email, password);
		console.debug(`User returned from login: ${JSON.stringify(user)}`);

		if (!user || !user._id) {
			console.warn(`User does not exist or login failed. User object: ${JSON.stringify(user)}`);
			return { status: false, message: 'Invalid credentials' };
		}

		// Create User Session
		try {
			console.debug(`Attempting to create session for user_id: ${user._id}`);
			const session = await auth.createSession({ userId: user._id });
			console.debug(`Session created: ${JSON.stringify(session)}`);
			const sessionCookie = auth.createSessionCookie(session);
			cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			await auth.updateUserAttributes(user._id, { lastAuthMethod: 'password' });

			return { status: true };
		} catch (error) {
			console.error(`Failed to create session: ${error}`);
			return { status: false, message: 'Failed to create session' };
		}
	} else {
		if (!auth) {
			console.error('Authentication system is not initialized');
			throw error(500, 'Internal Server Error');
		}

		// User is registered, and credentials are provided as a token
		const token = password;
		const user = await auth.checkUser({ email });

		if (!user) {
			console.warn('User does not exist');
			return { status: false, message: 'User does not exist' };
		}

		const result = await auth.consumeToken(token, user._id);

		if (result.status) {
			// Create User Session
			const session = await auth.createSession({ userId: user._id });

			const sessionCookie = auth.createSessionCookie(session);
			cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			await auth.updateUserAttributes(user._id, { lastAuthMethod: 'token' });
			return { status: true };
		} else {
			console.warn(`Token consumption failed: ${result.message}`);
			return result;
		}
	}
}

// Function create a new OTHER USER account and creating a session.
async function FirstUsersignUp(username: string, email: string, password: string, cookies: Cookies) {
	console.debug(`FirstUsersignUp called with username: ${username}, email: ${email}, password: ${password}, cookies: ${JSON.stringify(cookies)}`);
	if (!auth) {
		console.error('Authentication system is not initialized');
		throw error(500, 'Internal Server Error');
	}
	const user = await auth.createUser({
		password,
		email,
		username,
		role: 'admin',
		lastAuthMethod: 'password',
		is_registered: true
	});

	if (!user) {
		console.error('User creation failed');
		return { status: false, message: 'User does not exist' };
	}

	// Create User Session
	const session = await auth.createSession({ userId: user._id, expires: 3600000 }); // Ensure expires is provided
	if (!session || !session.session_id) {
		console.error('Session creation failed');
		return { status: false, message: 'Failed to create session' };
	}
	console.info(`Session created with ID: ${session.session_id} for user ID: ${user._id}`);

	// Create session cookie and set it
	const sessionCookie = auth.createSessionCookie(session);
	cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

	return { status: true };
}

// Function create a new OTHER USER account and creating a session.
async function finishRegistration(username: string, email: string, password: string, token: string, cookies: Cookies) {
	console.debug(`finishRegistration called with username: ${username}, email: ${email}, password: ${password}`);
	if (!auth) {
		console.error('Authentication system is not initialized');
		throw error(500, 'Internal Server Error');
	}
	const user = await auth.checkUser({ email });

	if (!user) return { status: false, message: 'User does not exist' };

	const result = await auth.consumeToken(token, user._id);

	if (result.status) {
		await auth.updateUserAttributes(user._id, {
			username,
			password,
			lastAuthMethod: 'password',
			is_registered: true
		});

		// Create User Session
		const session = await auth.createSession({ userId: user._id.toString() });
		const sessionCookie = auth.createSessionCookie(session);
		// Set the credentials cookie
		cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);

		return { status: true };
	} else {
		console.warn(`Token consumption failed: ${result.message}`);
		return result;
	}
}

interface ForgotPWCheckResult {
	status?: boolean;
	success?: boolean;
	message: string;
	token?: string;
	expiresIn?: number;
}

// Function for handling the Forgotten Password
async function forgotPWCheck(email: string): Promise<ForgotPWCheckResult> {
	try {
		if (!auth) {
			console.error('Authentication system is not initialized');
			throw error(500, 'Internal Server Error');
		}

		const expiresIn = 1 * 60 * 60 * 1000; // expiration in 1 hours
		const user = await auth.checkUser({ email });

		// The email address does not exist
		if (!user) return { success: false, message: 'User does not exist' };

		// Create a new token
		const token = await auth.createToken(user._id.toString(), expiresIn);

		return { success: true, message: 'Password reset token sent by Email', token, expiresIn };
	} catch (err: any) {
		console.error('An error occurred:', err);
		return { success: false, message: 'An error occurred' };
	}
}

// Function for handling the RESET Password
async function resetPWCheck(password: string, token: string, email: string, expiresIn: number) {
	try {
		if (!auth) {
			console.error('Authentication system is not initialized');
			//throw error(500, 'Internal Server Error');
		}
		// Obtain the user using auth.checkUser based on the email
		const user = await auth.checkUser({ email });
		if (!user) {
			console.warn('Invalid token: User does not exist');
			return { status: false, message: 'Invalid token' };
		}

		// Consume the token
		const validate = await auth.consumeToken(token, user._id.toString());

		if (validate.status) {
			// Check token expiration
			const currentTime = Date.now();
			const tokenExpiryTime = currentTime + expiresIn * 1000; // Convert expiresIn to milliseconds
			if (currentTime >= tokenExpiryTime) {
				console.warn('Token has expired');
				return { status: false, message: 'Token has expired' };
			}

			// Token is valid and not expired, proceed with password update
			auth.invalidateAllUserSessions(user._id.toString()); // Invalidate all user sessions
			const updateResult = await auth.updateUserPassword(email, password); // Pass the email and password

			if (updateResult.status) {
				return { status: true };
			} else {
				console.warn(`Password update failed: ${updateResult.message}`);
				return { status: false, message: updateResult.message };
			}
		} else {
			console.warn(`Token consumption failed: ${validate.message}`);
			return { status: false, message: validate.message };
		}
	} catch (err: any) {
		console.error('Password reset failed:', err);
		return { status: false, message: 'An error occurred' };
	}
}