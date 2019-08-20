# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Guillaume Martinez (lunik@tiwabbit.fr)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import

import pytest

from ansible.modules.source_control.gitlab_project import GitLabProject


def _dummy(x):
    """Dummy function.  Only used as a placeholder for toplevel definitions when the test is going
    to be skipped anyway"""
    return x


pytestmark = []
try:
    from .gitlab import (GitlabModuleTestCase,
                         python_version_match_requirement,
                         resp_get_group, resp_get_project_by_name, resp_create_project,
                         resp_get_project, resp_delete_project, resp_get_user,
                             resp_get_protected_branches, resp_create_protected_branch,
                             resp_delete_protected_branch)

    # Gitlab module requirements
    if python_version_match_requirement():
        from gitlab.v4.objects import Project, ProjectProtectedBranch
except ImportError:
    #pytestmark.append(pytest.mark.skip("Could not load gitlab module required for testing"))
    # Need to set these to something so that we don't fail when parsing
    GitlabModuleTestCase = object
    resp_get_group = _dummy
    resp_get_project_by_name = _dummy
    resp_create_project = _dummy
    resp_get_project = _dummy
    resp_delete_project = _dummy
    resp_get_user = _dummy
from httmock import with_httmock
# Unit tests requirements
try:
    from httmock import with_httmock  # noqa
except ImportError:
    #pytestmark.append(pytest.mark.skip("Could not load httmock module required for testing"))
    with_httmock = _dummy


class TestGitlabProject(GitlabModuleTestCase):
    @with_httmock(resp_get_user)
    def setUp(self):
        super(TestGitlabProject, self).setUp()

        self.gitlab_instance.user = self.gitlab_instance.users.get(1)
        self.moduleUtil = GitLabProject(module=self.mock_module, gitlab_instance=self.gitlab_instance)

    @with_httmock(resp_get_group)
    @with_httmock(resp_get_project_by_name)
    def test_project_exist(self):
        group = self.gitlab_instance.groups.get(1)

        rvalue = self.moduleUtil.existsProject(group, "diaspora-client")

        self.assertEqual(rvalue, True)

        rvalue = self.moduleUtil.existsProject(group, "missing-project")

        self.assertEqual(rvalue, False)


    @with_httmock(resp_get_group)
    @with_httmock(resp_create_project)
    @with_httmock(resp_create_protected_branch)
    def test_create_project(self):
        group = self.gitlab_instance.groups.get(1)
        project, branches = self.moduleUtil.createProject(group,
                        {"name": "Diaspora Client", "path": "diaspora-client", "namespace_id": group.id},
                        [{"merge_access_level": 'master', "name": "*-stable", "push_access_level": 'master'}])

        self.assertEqual(type(project), Project)
        self.assertEqual(project.name, "Diaspora Client")
        self.assertEqual(type(branches[0]), ProjectProtectedBranch)
        self.assertEqual(branches[0].name, "*-stable")


    @with_httmock(resp_get_project)
    @with_httmock(resp_get_protected_branches)
    @with_httmock(resp_create_protected_branch)
    @with_httmock(resp_delete_protected_branch)
    def test_update_project(self):
        project = self.gitlab_instance.projects.get(1)

        changed, newProject, newBranches = self.moduleUtil.updateProject(project, {"name": "New Name"},
                        [{"merge_access_level": 'master', "name": "*-stable", "push_access_level": 'master'}])

        self.assertEqual(changed, True)
        self.assertEqual(type(newProject), Project)
        self.assertEqual(newProject.name, "New Name")
        self.assertEqual(type(newBranches[1]), ProjectProtectedBranch)
        self.assertEqual(newBranches[1].name, "*-stable")

        changed, newProject, newBranches = self.moduleUtil.updateProject(project, {"name": "New Name"},
                        [{"merge_access_level": 'master', "name": "*-stable", "push_access_level": 'master'}])

        self.assertEqual(changed, False)
        self.assertEqual(newProject.name, "New Name")
        self.assertEqual(type(newBranches[1]), ProjectProtectedBranch)
        self.assertEqual(newBranches[1].name, "*-stable")

        # Delete branch
        changed, newProject, newBranches = self.moduleUtil.updateProject(project, {"name": "New Name"}, [])

        self.assertEqual(changed, True)
        self.assertEqual(newProject.name, "New Name")
        self.assertEqual(type(newBranches[0]), ProjectProtectedBranch)
        self.assertEqual(newBranches[0].name, "master")
        self.assertEqual(len(newBranches), 1)

        # Create branch
        changed, newProject, newBranches = self.moduleUtil.updateProject(project, {"name": "New Name"},
                        [{"merge_access_level": 'master', "name": "V*", "push_access_level": 'master'},
                         {"merge_access_level": 'master', "name": "*-stable", "push_access_level": 'master'}])

        self.assertEqual(changed, True)
        self.assertEqual(type(newProject), Project)
        self.assertEqual(newProject.name, "New Name")
        self.assertEqual(len(newBranches), 3)


    @with_httmock(resp_get_group)
    @with_httmock(resp_get_project_by_name)
    @with_httmock(resp_delete_project)
    def test_delete_project(self):
        group = self.gitlab_instance.groups.get(1)

        self.moduleUtil.existsProject(group, "diaspora-client")

        self.assertEqual(self.moduleUtil.deleteProject(), None)
