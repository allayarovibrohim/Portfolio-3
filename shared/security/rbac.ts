import { ForbiddenError } from "../http/errors";

export const assertPermission = (grantedPermissions: string[], requiredPermissions: string[]) => {
  const missing = requiredPermissions.filter((permission) => !grantedPermissions.includes(permission));

  if (missing.length > 0) {
    throw new ForbiddenError(`Missing permissions: ${missing.join(", ")}`);
  }
};

export const flattenRolePermissions = (
  roleAssignments: Array<{
    role: {
      permissions: Array<{
        permission: {
          key: string;
        };
      }>;
    };
  }>,
) =>
  Array.from(
    new Set(
      roleAssignments.flatMap((assignment) =>
        assignment.role.permissions.map((entry) => entry.permission.key),
      ),
    ),
  );
