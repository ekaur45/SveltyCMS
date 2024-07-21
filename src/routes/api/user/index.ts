import { json, type RequestHandler } from '@sveltejs/kit';
import { auth } from '@api/databases/db';
import { superValidate } from 'sveltekit-superforms/server';
import { addUserTokenSchema } from '@utils/formSchemas';
import { zod } from 'sveltekit-superforms/adapters';
import { error } from '@sveltejs/kit';

export const GET: RequestHandler = async () => {
	try {
		const users = await auth.getUsers();
		return json(users);
	} catch (err) {
		console.error(err);
		throw error(500, 'Internal Server Error');
	}
};

export const POST: RequestHandler = async ({ request }) => {
	try {
		const addUserForm = await superValidate(request, zod(addUserTokenSchema));
		const { email, role, expiresIn } = addUserForm.data;
		const expirationTime = {
			'2 hrs': 7200,
			'12 hrs': 43200,
			'2 days': 172800,
			'1 week': 604800
		}[expiresIn];

		if (!expirationTime) {
			return new Response(JSON.stringify({ form: addUserForm, message: 'Invalid value for token validity' }), { status: 400 });
		}

		if (await auth.checkUser({ email })) {
			return new Response(JSON.stringify({ message: 'User already exists' }), { status: 400 });
		}

		const newUser = await auth.createUser({ email, role, lastAuthMethod: 'password', is_registered: false });
		const token = await auth.createToken(newUser._id, expirationTime * 1000);

		// Send the token via email (this should be implemented)
		await fetch('/api/sendMail', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				email,
				subject: 'User Token',
				message: 'User Token',
				templateName: 'userToken',
				props: { email, token, role, expiresIn: expirationTime }
			})
		});

		return json(newUser);
	} catch (err) {
		console.error(err);
		throw error(500, 'Internal Server Error');
	}
};
