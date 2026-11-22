// The example policy bundle (docs/policy.md). Install it as policy-bundle.jws next to site.jws.
permit (principal, action, resource) unless { resource == Route::"admin" };
permit (principal in Group::"admins", action, resource == Route::"admin");
