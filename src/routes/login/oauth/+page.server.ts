import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';

// Auth
import { auth, googleAuth } from '@api/databases/db';
import { google } from 'googleapis';
import type { User } from '@src/auth/types';
// Stores
import { systemLanguage } from '@stores/store';
import { get } from 'svelte/store';

export const load: PageServerLoad = async ({ url, cookies, fetch }) => {
	const code = url.searchParams.get('code');
	console.log('code: ', code);

	const result: Result = {
		errors: [],
		success: true,
		message: '',
		data: {
			needSignIn: false
		}
	};

	if (!code) {
		throw redirect(302, '/login');
	}

	if (!auth || !googleAuth) {
		console.error('Authentication system is not initialized');
		throw new Error('Internal Server Error');
	}

	try {
		const { tokens } = await googleAuth.getToken(code);
		googleAuth.setCredentials(tokens);
		const oauth2 = google.oauth2({ auth: googleAuth, version: 'v2' });

		const { data: googleUser } = await oauth2.userinfo.get();
		console.log('googleUser: ', googleUser);

		const getUser = async (): Promise<[User | null, boolean]> => {
			const existingUser = await auth.checkUser({ email: googleUser.email });
			if (existingUser) return [existingUser, false];

			// Probably will never happen but just to be sure.
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
			} else return [null, true];
		};

		const [user, needSignIn] = await getUser();

		if (!needSignIn) {
			if (!user) throw new Error('User not found.');
			if ((user as any).blocked) return { status: false, message: 'User is blocked' };

			// Create User Session
			const session = await auth.createSession({ userId: user._id?.toString() as string });
			const sessionCookie = auth.createSessionCookie(session);
			cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
			await auth.updateUserAttributes(user, { lastAuthMethod: 'password' });
		}
		result.data = { needSignIn };
	} catch (e) {
		console.log(e);
		throw redirect(302, '/login');
	}
	if (!result.data.needSignIn) throw redirect(303, '/');

	return result;
};

export const actions: Actions = {
	// default action
	default: async ({ request, url, cookies }) => {
		const data = await request.formData();
		const token = data.get('token');

		const result: Result = {
			errors: [],
			success: true,
			message: '',
			data: {}
		};

		if (!token || typeof token !== 'string') {
			result.errors.push('Token not found');
			result.success = false;
			return result;
		}

		const code = url.searchParams.get('code');
		console.log('code: ', code);

		if (!code) {
			throw redirect(302, '/login');
		}

		if (!auth || !googleAuth) {
			console.error('Authentication system is not initialized');
			return { success: false, message: 'Internal Server Error' };
		}

		try {
			const { tokens } = await googleAuth.getToken(code);
			googleAuth.setCredentials(tokens);
			const oauth2 = google.oauth2({ auth: googleAuth, version: 'v2' });

			const { data: googleUser } = await oauth2.userinfo.get();
			console.log('googleUser: ', googleUser);

			// Get existing user if available
			const existingUser = await auth.checkUser({ email: googleUser.email });

			// If the user doesn't exist, create a new one
			if (!existingUser) {
				const sendWelcomeEmail = async (email: string, username: string) => {
					try {
						await fetch('/api/sendMail', {
							method: 'POST',
							headers: {
								'Content-Type': 'application/json'
							},
							body: JSON.stringify({
								email,
								subject: `New registration ${username}`,
								message: `New registration ${username}`,
								templateName: 'welcomeUser',
								lang: get(systemLanguage),
								props: {
									username,
									email
								}
							})
						});
					} catch (error) {
						console.error('Error sending welcome email:', error);
						throw new Error('Failed to send welcome email');
					}
				};

				// Check if it's the first user
				const isFirst = (await auth.getUserCount()) === 0;

				// Create User
				const user = await auth.createUser({
					email: googleUser.email,
					username: googleUser.name ?? '',
					role: isFirst ? 'admin' : 'user',
					lastAuthMethod: 'password',
					is_registered: true,
					blocked: false
				});

				// Send welcome email
				await sendWelcomeEmail(googleUser.email, googleUser.name);

				// Create User Session
				const session = await auth.createSession({ userId: user._id?.toString() as string });
				const sessionCookie = auth.createSessionCookie(session);
				cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
				await auth.updateUserAttributes(user, { lastAuthMethod: 'password' });

				result.data = { user };
			} else {
				// User already exists, consume token
				const validate = await auth.consumeToken(token, existingUser._id?.toString() as string); // Consume the token

				if (validate.status) {
					// Create User Session
					const session = await auth.createSession({ userId: existingUser._id?.toString() as string });
					const sessionCookie = auth.createSessionCookie(session);
					cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.attributes);
					await auth.updateUserAttributes(existingUser, { lastAuthMethod: 'password' });

					result.data = { user: existingUser };
				} else {
					result.errors.push('Invalid token');
					result.success = false;
				}
			}
		} catch (e) {
			console.error('error:', e);
			throw redirect(302, '/login');
		}

		if (result.success) throw redirect(303, '/');
		else return result;
	}
};
