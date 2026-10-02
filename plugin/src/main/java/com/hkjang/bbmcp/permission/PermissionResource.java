package com.hkjang.bbmcp.permission;

import com.atlassian.bitbucket.permission.Permission;
import com.atlassian.bitbucket.permission.PermissionService;
import com.atlassian.bitbucket.project.Project;
import com.atlassian.bitbucket.project.ProjectService;
import com.atlassian.bitbucket.repository.Repository;
import com.atlassian.bitbucket.repository.RepositoryService;
import com.atlassian.bitbucket.user.ApplicationUser;
import com.atlassian.bitbucket.user.SecurityService;
import com.atlassian.bitbucket.user.UserService;
import com.atlassian.bitbucket.util.Operation;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Read-only effective permission lookups for the bbmcp gateway.
 *
 * The gateway never recomputes Bitbucket's permission model: it asks here, and
 * this resource delegates to Bitbucket's own PermissionService so that global,
 * project, repository, group, inherited and public-repository rules all agree
 * with what Bitbucket itself would decide.
 *
 * Deliberately absent: anything that changes state. This plugin cannot grant,
 * revoke or modify permissions.
 */
@Named("mcpPermissionResource")
@Path("/")
@Produces({MediaType.APPLICATION_JSON})
public class PermissionResource {

    private final PermissionService permissionService;
    private final ProjectService projectService;
    private final RepositoryService repositoryService;
    private final UserService userService;
    private final SecurityService securityService;

    @Inject
    public PermissionResource(@ComponentImport PermissionService permissionService,
                              @ComponentImport ProjectService projectService,
                              @ComponentImport RepositoryService repositoryService,
                              @ComponentImport UserService userService,
                              @ComponentImport SecurityService securityService) {
        this.permissionService = permissionService;
        this.projectService = projectService;
        this.repositoryService = repositoryService;
        this.userService = userService;
        this.securityService = securityService;
    }

    @GET
    @Path("/health")
    public Response health() {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("status", "ok");
        out.put("plugin", "bbmcp-permission-plugin");
        out.put("api", "1.0");
        return Response.ok(out).build();
    }

    @GET
    @Path("/users/{username}/projects/{projectKey}")
    public Response projectPermission(@PathParam("username") final String username,
                                      @PathParam("projectKey") final String projectKey) {
        final ApplicationUser user = userService.getUserByName(username);
        if (user == null) {
            return notFound("사용자를 찾을 수 없습니다: " + username);
        }

        // The lookup itself needs elevated rights: the gateway's service
        // account must be able to ask about another user's permissions.
        final Project project = withAdmin(new Operation<Project, RuntimeException>() {
            @Override
            public Project perform() {
                return projectService.getByKey(projectKey);
            }
        });
        if (project == null) {
            return notFound("프로젝트를 찾을 수 없습니다: " + projectKey);
        }

        boolean read = permissionService.hasProjectPermission(user, project, Permission.PROJECT_READ);
        boolean write = permissionService.hasProjectPermission(user, project, Permission.PROJECT_WRITE);
        boolean admin = permissionService.hasProjectPermission(user, project, Permission.PROJECT_ADMIN);

        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("username", user.getName());
        out.put("userId", user.getId());
        out.put("project", project.getKey());
        out.put("permissions", flags(read, write, admin));
        out.put("effective", effective(read, write, admin));
        out.put("global", globalFlags(user));
        return Response.ok(out).build();
    }

    @GET
    @Path("/users/{username}/repositories/{projectKey}/{repositorySlug}")
    public Response repositoryPermission(@PathParam("username") final String username,
                                         @PathParam("projectKey") final String projectKey,
                                         @PathParam("repositorySlug") final String repositorySlug) {
        final ApplicationUser user = userService.getUserByName(username);
        if (user == null) {
            return notFound("사용자를 찾을 수 없습니다: " + username);
        }

        final Repository repository = withAdmin(new Operation<Repository, RuntimeException>() {
            @Override
            public Repository perform() {
                return repositoryService.getBySlug(projectKey, repositorySlug);
            }
        });
        if (repository == null) {
            return notFound("저장소를 찾을 수 없습니다: " + projectKey + "/" + repositorySlug);
        }

        boolean read = permissionService.hasRepositoryPermission(user, repository, Permission.REPO_READ);
        boolean write = permissionService.hasRepositoryPermission(user, repository, Permission.REPO_WRITE);
        boolean admin = permissionService.hasRepositoryPermission(user, repository, Permission.REPO_ADMIN);

        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("username", user.getName());
        out.put("userId", user.getId());
        out.put("project", repository.getProject().getKey());
        out.put("repository", repository.getSlug());
        out.put("repositoryId", repository.getId());
        out.put("public", repository.isPublic());
        out.put("permissions", flags(read, write, admin));
        out.put("effective", effective(read, write, admin));
        out.put("global", globalFlags(user));
        return Response.ok(out).build();
    }

    private Map<String, Object> globalFlags(ApplicationUser user) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("licensedUser", permissionService.hasGlobalPermission(user, Permission.LICENSED_USER));
        out.put("projectCreate", permissionService.hasGlobalPermission(user, Permission.PROJECT_CREATE));
        out.put("admin", permissionService.hasGlobalPermission(user, Permission.ADMIN));
        out.put("sysAdmin", permissionService.hasGlobalPermission(user, Permission.SYS_ADMIN));
        return out;
    }

    private static Map<String, Object> flags(boolean read, boolean write, boolean admin) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("read", read);
        out.put("write", write);
        out.put("admin", admin);
        return out;
    }

    private static String effective(boolean read, boolean write, boolean admin) {
        if (admin) {
            return "ADMIN";
        }
        if (write) {
            return "WRITE";
        }
        if (read) {
            return "READ";
        }
        return "NONE";
    }

    private <T> T withAdmin(Operation<T, RuntimeException> operation) {
        return securityService
                .withPermission(Permission.SYS_ADMIN, "bbmcp permission lookup")
                .call(operation);
    }

    private static Response notFound(String message) {
        Map<String, Object> out = new LinkedHashMap<String, Object>();
        out.put("error", message);
        return Response.status(Response.Status.NOT_FOUND).entity(out).build();
    }
}
