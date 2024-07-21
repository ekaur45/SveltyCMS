// Define the admin role explicitly as it has all permissions by default.
export const adminRole = 'admin';

export const otherRoles = ['developer', 'editor', 'user'] as const;

// Combining all roles for export
export const roles = [adminRole, ...otherRoles] as const;

// List of possible permissions for simplicity and type safety.
export const permissions = [
	'create', // Allows creating new content.
	'read', // Allows viewing content.
	'write', // Allows modifying existing content.
	'delete' // Allows removing content.
] as const;

// Type for the specific actions a role can perform.
export type PermissionAction = (typeof permissions)[number];

// Permission interface to define what each permission can do
export interface Permission {
	id: string;
	action: PermissionAction;
	contextId: string; // This could be a collectionId or widgetId indicating scope
	description?: string;
	contextType: 'collection' | 'widget'; // Distinguishes between collections and widgets
	requires2FA?: boolean; // Indicates if this permission requires two-factor authentication
}

// Define the type for a Role with dynamically assigned permissions
export interface Role {
	id: string;
	name: string;
	description?: string;
	permissions: Permission[]; // This includes permission IDs which can be resolved to actual permissions
}

// Define the type for RateLimit
export interface RateLimit {
	userId: string; // The ID of the user
	action: PermissionAction; // The action being rate limited
	limit: number; // Number of allowed actions
	windowMs: number; // Time window in milliseconds
	current: number; // Current count of actions
	lastActionAt: Date; // Time of the last action
}

// User interface represents a user in the system.
export interface User {
	_id: string; // Unique identifier for the user
	email: string; // Email address of the user
	password?: string; // Hashed password of the user
	role: string; // Role of the user (e.g., admin, developer, editor, user)
	username?: string; // Username of the user
	avatar?: string; // URL of the user's avatar image
	lastAuthMethod?: string; // The last authentication method used by the user
	lastActiveAt?: Date; // The last time the user was active
	expiresAt?: Date; // When the reset token expires
	is_registered?: boolean; // Indicates if the user has completed registration
	blocked?: boolean; // Indicates if the user is blocked
	resetRequestedAt?: string; // The last time the user requested a password reset
	resetToken?: string; // Token for resetting the user's password
	failedAttempts: number; // Tracks the number of consecutive failed login attempts
	lockoutUntil?: Date | null; // Time until which the user is locked out of their account
	is2FAEnabled?: boolean; // Indicates if the user has enabled two-factor authentication
	permissions?: Permission[]; // Optional user-specific permissions
}

// Session interface represents a session in the system.
export interface Session {
	_id: string; // Unique identifier for the session
	userId: string; // The ID of the user who owns the session
	expires: Date; // When the session expires
}

// Token interface represents a token in the system.
export interface Token {
	id: string; // Unique identifier for the token
	userId: string; // The ID of the user who owns the token
	token: string; // The token string
	email?: string; // Email associated with the token
	expires: Date; // When the token expires
}

// Collection interface to encapsulate permissions specific to collections.
export interface Collection {
	id: string;
	name: string;
	permissions: Permission[]; // Permissions specific to this collection
}

// Define the type for a Cookie
export type Cookie = {
	name: string;
	value: string;
	attributes: {
		sameSite: boolean | 'lax' | 'strict' | 'none' | undefined;
		path: string;
		httpOnly: true;
		expires: Date;
		secure: boolean;
	};
};

// Utility function to check if a user has a specific permission in a given context.
function hasUserPermission(user: User, action: PermissionAction, contextId: string): boolean {
	return (
		user.permissions?.some(
			(permission) => permission.action === action && (permission.contextId === contextId || permission.contextId === 'global')
		) ?? false
	);
}

// Utility function to check if a role has a specific permission in a given context.
function hasRolePermission(role: Role, action: PermissionAction, contextId: string): boolean {
	return role.permissions.some(
		(permission) => permission.action === action && (permission.contextId === contextId || permission.contextId === 'global')
	);
}

// Utility function to check if the action is within the rate limit.
function checkRateLimit(rateLimits: RateLimit[], userId: string, action: PermissionAction): boolean {
	const rateLimit = rateLimits.find((rl) => rl.userId === userId && rl.action === action);
	if (rateLimit) {
		const now = new Date();
		if (now.getTime() - rateLimit.lastActionAt.getTime() < rateLimit.windowMs) {
			if (rateLimit.current >= rateLimit.limit) {
				return false;
			}
			rateLimit.current++;
		} else {
			rateLimit.current = 1;
			rateLimit.lastActionAt = now;
		}
	}
	return true;
}

// Main utility function to check if a user has a specific permission in a given context considering both user and role-based permissions.
export function hasPermission(user: User, roles: Role[], action: PermissionAction, contextId: string, rateLimits: RateLimit[]): boolean {
	// Check if the action is within the rate limit
	if (!checkRateLimit(rateLimits, user._id, action)) {
		return false;
	}

	// Check user-specific permissions first
	if (hasUserPermission(user, action, contextId)) {
		return true;
	}

	// Find the user's role object
	const userRole = roles.find((role) => role.id === user.role);
	if (!userRole) {
		return false; // Role not found
	}

	// Check if the user has the required permission through their role
	const hasPerm = hasRolePermission(userRole, action, contextId);

	// Check if 2FA is required and if the user has 2FA enabled
	const requires2FA = userRole.permissions.some((permission) => permission.action === action && permission.requires2FA);
	if (requires2FA && !user.is2FAEnabled) {
		return false;
	}

	return hasPerm;
}

// Define default permissions for roles. Could be loaded from a database or configuration file for adaptability.
export const defaultPermissions = {
	admin: permissions.map((permission) => ({
		action: permission,
		contextId: 'global', // Admin has global access for all actions.
		description: `Admin default permission for ${permission}`,
		requires2FA: false
	}))
	// Additional roles can be defined here
};

// Icons for permissions
export const icon = {
	create: 'bi:plus-circle-fill',
	read: 'bi:eye-fill',
	write: 'bi:pencil-fill',
	delete: 'bi:trash-fill'
} as const;

// Color coding for permissions
export const color = {
	disabled: {
		create: 'variant-outline-primary',
		read: 'variant-outline-tertiary',
		write: 'variant-outline-warning',
		delete: 'variant-outline-error'
	},
	enabled: {
		create: 'variant-filled-primary',
		read: 'variant-filled-tertiary',
		write: 'variant-filled-warning',
		delete: 'variant-filled-error'
	}
} as const;

// Sanitizes a permissions dictionary by removing empty roles
export const sanitizePermissions = (permissions: any) => {
	const res = Object.keys(permissions).reduce((acc, role) => {
		acc[role] = Object.keys(permissions[role]).reduce((acc, action) => {
			if (permissions[role][action] != defaultPermissions[role]?.find((p) => p.action === action)) {
				acc[action] = permissions[role][action];
			}
			return acc;
		}, {});
		if (Object.keys(acc[role]).length == 0) delete acc[role];
		return acc;
	}, {});
	return Object.keys(res).length === 0 ? undefined : res;
};

// Define the type for a Model
export interface Model<T> {
	create(data: Partial<T>): Promise<T>;
	findOne(query: Partial<T>): Promise<T | null>;
	find(query: Partial<T>): Promise<T[]>;
	updateOne(query: Partial<T>, update: Partial<T>): Promise<void>;
	deleteOne(query: Partial<T>): Promise<void>;
	countDocuments(query?: Partial<T>): Promise<number>;
}

// Define the type for a Widgets
export type WidgetId = string;
