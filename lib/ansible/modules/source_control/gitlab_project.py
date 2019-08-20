#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Guillaume Martinez (lunik@tiwabbit.fr)
# Copyright: (c) 2015, Werner Dijkerman (ikben@werner-dijkerman.nl)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gitlab_project
short_description: Creates/updates/deletes Gitlab Projects
description:
  - When the project does not exist in Gitlab, it will be created.
  - When the project does exists and state=absent, the project will be deleted.
  - When changes are made to the project, the project will be updated.
version_added: "2.1"
author:
  - Werner Dijkerman (@dj-wasabi)
  - Guillaume Martinez (@Lunik)
requirements:
  - python >= 2.7
  - python-gitlab python module
extends_documentation_fragment:
    - auth_basic
options:
  server_url:
    description:
      - The URL of the Gitlab server, with protocol (i.e. http or https).
    type: str
  login_user:
    description:
      - Gitlab user name.
    type: str
  login_password:
    description:
      - Gitlab password for login_user
    type: str
  api_token:
    description:
      - Gitlab token for logging in.
    type: str
    aliases:
      - login_token
  group:
    description:
      - Id or The full path of the group of which this projects belongs to.
    type: str
  name:
    description:
      - The name of the project
    required: true
    type: str
  path:
    description:
      - The path of the project you want to create, this will be server_url/<group>/path
      - If not supplied, name will be used.
    type: str
  description:
    description:
      - An description for the project.
    type: str
  issues_enabled:
    description:
      - Whether you want to create issues or not.
      - Possible values are true and false.
    type: bool
    default: yes
  merge_requests_enabled:
    description:
      - If merge requests can be made or not.
      - Possible values are true and false.
    type: bool
    default: yes
  wiki_enabled:
    description:
      - If an wiki for this project should be available or not.
      - Possible values are true and false.
    type: bool
    default: yes
  snippets_enabled:
    description:
      - If creating snippets should be available or not.
      - Possible values are true and false.
    type: bool
    default: yes
  visibility:
    description:
      - Private. Project access must be granted explicitly for each user.
      - Internal. The project can be cloned by any logged in user.
      - Public. The project can be cloned without any authentication.
    default: private
    type: str
    choices: ["private", "internal", "public"]
    aliases:
      - visibility_level
  import_url:
    description:
      - Git repository which will be imported into gitlab.
      - Gitlab server needs read access to this git repository.
    required: false
    type: str
  state:
    description:
      - create or delete project.
      - Possible values are present and absent.
    default: present
    type: str
    choices: ["present", "absent"]
  protected_branches : 
    description :
      - List of branches you want protected.
      - 'master' branch is always protected by default.
      - Each branch is a dictionnary
    suboptions
      name :
        description :
          - the name of the protected branch.
        required : true
      merge_access_level : 
        description :
          - access level for merges
        choices :
          - master
          - developer
      push_access_level :
        description :
          - access level for pushes
        choices :
          - master
          - developer
      
    required : false
    type : list
'''

EXAMPLES = '''
- name: Delete Gitlab Project
  gitlab_project:
    api_url: https://gitlab.example.com/
    api_token: "{{ access_token }}"
    validate_certs: False
    name: my_first_project
    state: absent
  delegate_to: localhost
- name: Create Gitlab Project in group Ansible
  gitlab_project:
    api_url: https://gitlab.example.com/
    validate_certs: True
    api_username: dj-wasabi
    api_password: "MySecretPassword"
    name: my_first_project
    group: ansible
    issues_enabled: False
    wiki_enabled: True
    snippets_enabled: True
    import_url: http://git.example.com/example/lab.git
    state: present
    protected_branches :
    - name : "V*"
      merge_access_level : master
      push_access_level : master
    - name : "*-stable"
      merge_access_level : master
      push_access_level : developer
  delegate_to: localhost
'''

RETURN = '''
msg:
  description: Success or failure message
  returned: always
  type: str
  sample: "Success"
result:
  description: json parsed response from the server
  returned: always
  type: dict
error:
  description: the error message returned by the Gitlab API
  returned: failed
  type: str
  sample: "400: path is already in use"
project:
  description: API object
  returned: always
  type: dict
protected_branches:
  description: list of API objects
  returned: always
  type: list
'''

import os
import traceback


DEFAUT = 'default'

GITLAB_IMP_ERR = None
try:
    import gitlab
    HAS_GITLAB_PACKAGE = True
except Exception:
    GITLAB_IMP_ERR = traceback.format_exc()
    HAS_GITLAB_PACKAGE = False

from ansible.module_utils.api import basic_auth_argument_spec
from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native

from ansible.module_utils.gitlab import findGroup, findProject



class GitLabProject(object):
    def __init__(self, module, gitlab_instance):
        self._module = module
        self._gitlab = gitlab_instance
        self.projectObject = None

    '''
    @param project_name Name of the project
    @param namespace Namespace Object (User or Group)
    @param options Options of the project
    @param branches Protected branches of the project
    '''
    def createOrUpdateProject(self, project_name, namespace, options, branches):
      
        changed = False

        # Because we have already call userExists in main()
        if self.projectObject is None:
            project, ret_branches = self.createProject(namespace, {
                'name': project_name,
                'path': options['path'],
                'description': options['description'],
                'issues_enabled': options['issues_enabled'],
                'merge_requests_enabled': options['merge_requests_enabled'],
                'wiki_enabled': options['wiki_enabled'],
                'snippets_enabled': options['snippets_enabled'],
                'visibility': options['visibility'],
                'import_url': options['import_url']}, branches)
            changed = True
        else:
            changed, project, ret_branches = self.updateProject(self.projectObject, {
                    'name': project_name,
                    'description': options['description'],
                    'issues_enabled': options['issues_enabled'],
                    'merge_requests_enabled': options['merge_requests_enabled'],
                    'wiki_enabled': options['wiki_enabled'],
                    'snippets_enabled': options['snippets_enabled'],
                    'visibility': options['visibility']}, branches)

        self.projectObject = project
        if changed:
            if self._module.check_mode:
                self._module.exit_json(changed=True, msg="Successfully created or updated the project %s" % project_name)

            try:
                project.save()
            except Exception as e:
                self._module.fail_json(msg="Failed update project: %s " % e)
            return True, ret_branches
        else:
            return False, ret_branches

    '''
    @param namespace Namespace Object (User or Group)
    @param arguments Attributs of the project
    @param branches Protected branches of the project
    '''
    def createProject(self, namespace, arguments, branches):
        
        if self._module.check_mode:
            return True, []

        arguments['namespace_id'] = namespace.id
        try:
            project = self._gitlab.projects.create(arguments)
        except (gitlab.exceptions.GitlabCreateError) as e:
            self._module.fail_json(msg="Failed to create project: %s " % to_native(e))

        # Create protected branches

        ret_branches = []
        already_protected = []
        
        branches.reverse() # In case of duplicate entries, olny the last declared one will be considered
        for branche in branches :
            if branche['name'] not in already_protected :
                p_branch = self.create_protected_branch(project, branche)
                ret_branches.append(p_branch)
                already_protected.append(p_branch.name)

        # master is protected by default
        if 'master' not in already_protected :
            ret_branches.append(
                self.create_protected_branch(project, 
                                             {'name': 'master',
                                              'merge_access_level': 'master',
                                              'push_access_level': 'master'}
                                             )
                )
        return (project, ret_branches)

    '''
    @param project Project Object
    @param name name of protected branch
    @param branch dict with keys 'name', 'merge_access_level' and 'push_access_level'
    '''
    def create_protected_branch(self, project, branch) :
        p_branch = project.protectedbranches.create({
                'name': branch['name'],
                'merge_access_level': gitlab_access(branch['merge_access_level']),
                'push_access_level': gitlab_access(branch['push_access_level'])
            })
        return p_branch

    '''
    @param project Project Object
    @param branches Protected branches of the project
    @param changed boolean
    '''
    def update_protected_branches(self, project, branches, changed) :

        if branches is None :
            branches = [] # Avoid "'NoneType' object is not iterable"

        protected_branches = project.protectedbranches.list()
        branches_to_add = [b for b in branches]
        ret_branches = []
        
        # Update existing branches

        for p_branch in protected_branches :

            branch_already_protected = None

            for branch in branches :
                if p_branch.name == branch['name'] :
                    branch_already_protected = branch
                    branches_to_add.remove(branch)
                    break # no need to continue loop since branch has been found
                
            if branch_already_protected is None : # Branch is not protected in playbook
                if  p_branch.name != 'master' :
                    if self._module.check_mode : return True, project, []
                    p_branch.delete()
                    changed = True

                else : # master stay protected, but its access may need changes
                    if p_branch.merge_access_levels[0]['access_level'] != gitlab_access('master') or p_branch.push_access_levels[0]['access_level'] != gitlab_access('master'):
                        if self._module.check_mode : return True, project, []
                        p_branch.delete()
                        p_branch = self.create_protected_branch(project, {'name' : 'master', 'merge_access_level': 'master', 'push_access_level': 'master'})
                        changed = True
                    ret_branches.append(p_branch)

            else : # update the protected branch if needed
                if p_branch.merge_access_levels[0]['access_level'] != gitlab_access(branch_already_protected['merge_access_level']) or p_branch.push_access_levels[0]['access_level'] != gitlab_access(branch_already_protected['push_access_level']):
                    if self._module.check_mode : return True, project, []
                    p_branch.delete()
                    p_branch = self.create_protected_branch(project, branch_already_protected)
                    changed = True
                ret_branches.append(p_branch)

        # Add new branches

        for new_branch in branches_to_add :
            if self._module.check_mode : return True, project, []
            p_branch = self.create_protected_branch(project, new_branch)
            ret_branches.append(p_branch)
            changed = True
            
        if self._module.check_mode : return True, project, []

        if not changed : ret_branches = protected_branches

        return changed, project, ret_branches

    '''
    @param project Project Object
    @param arguments Attributs of the project
    @param branches Protected branches of the project
    '''
    def updateProject(self, project, arguments, branches):
        changed = False
        for arg_key, arg_value in arguments.items():
            if arguments[arg_key] is not None:
                if getattr(project, arg_key) != arguments[arg_key]:
                    setattr(project, arg_key, arguments[arg_key])
                    changed = True
            
        return self.update_protected_branches(project, branches, changed)


    def deleteProject(self):
        if self._module.check_mode:
            return True

        project = self.projectObject

        return project.delete()

    '''
    @param namespace User/Group object
    @param name Name of the project
    '''
    def existsProject(self, namespace, path):
        # When project exists, object will be stored in self.projectObject.
        project = findProject(self._gitlab, namespace.full_path + '/' + path)
        if project:
            self.projectObject = project
            return True
        return False


def deprecation_warning(module):
    deprecated_aliases = ['login_token']
    module.deprecate("Aliases \'{aliases}\' are deprecated".format(aliases='\', \''.join(deprecated_aliases)), "2.10")


def gitlab_access(access) :
    ''' Returns Gitlab constant corresponding to access,
    by giving MAINTAINER_ACCESS by default'''
    if access == "developer" : return gitlab.DEVELOPER_ACCESS
    return gitlab.MAINTAINER_ACCESS




def main():
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        server_url=dict(type='str', required=True, removed_in_version="2.10"),
        login_user=dict(type='str', no_log=True, removed_in_version="2.10"),
        login_password=dict(type='str', no_log=True, removed_in_version="2.10"),
        api_token=dict(type='str', no_log=True, aliases=["login_token"]),
        group=dict(type='str'),
        name=dict(type='str', required=True),
        path=dict(type='str'),
        description=dict(type='str'),
        issues_enabled=dict(type='bool', default=True),
        merge_requests_enabled=dict(type='bool', default=True),
        wiki_enabled=dict(type='bool', default=True),
        snippets_enabled=dict(default=True, type='bool'),
        visibility=dict(type='str', default="private", choices=["internal", "private", "public"], aliases=["visibility_level"]),
        import_url=dict(type='str'),
        state=dict(type='str', default="present", choices=["absent", "present"]),
        protected_branches=dict(type='list', elements='dict'),  
    ))
    
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ['api_url', 'server_url'],
            ['api_username', 'login_user'],
            ['api_password', 'login_password'],
            ['api_username', 'api_token'],
            ['api_password', 'api_token'],
            ['login_user', 'login_token'],
            ['login_password', 'login_token']
        ],
        required_together=[
            ['api_username', 'api_password'],
            ['login_user', 'login_password'],
        ],
        required_one_of=[
            ['api_username', 'api_token', 'login_user', 'login_token']
        ],
        supports_check_mode=True,
    )

    deprecation_warning(module)

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']

    api_url = module.params['api_url']
    validate_certs = module.params['validate_certs']
    api_user = module.params['api_username']
    api_password = module.params['api_password']

    gitlab_url = server_url if api_url is None else api_url
    gitlab_user = login_user if api_user is None else api_user
    gitlab_password = login_password if api_password is None else api_password
    gitlab_token = module.params['api_token']

    group_identifier = module.params['group']
    project_name = module.params['name']
    project_path = module.params['path']
    project_description = module.params['description']
    issues_enabled = module.params['issues_enabled']
    merge_requests_enabled = module.params['merge_requests_enabled']
    wiki_enabled = module.params['wiki_enabled']
    snippets_enabled = module.params['snippets_enabled']
    visibility = module.params['visibility']
    import_url = module.params['import_url']
    state = module.params['state']
    protected_branches = module.params['protected_branches']
    
    branches = protected_branches if protected_branches is not None else []
    
    # Branches verification
    
    for branch in branches :
        if 'name' not in branch :
            module.fail_json(msg="Each element of 'protected_branch' must have a name.")
        if 'merge_access_level' not in branch :
            branch['merge_access_level'] = 'master'
        if 'push_access_level' not in branch :
            branch['push_access_level'] = 'master'


    if not HAS_GITLAB_PACKAGE:
        module.fail_json(msg=missing_required_lib("python-gitlab"), exception=GITLAB_IMP_ERR)

    try:
        gitlab_instance = gitlab.Gitlab(url=gitlab_url, ssl_verify=validate_certs, email=gitlab_user, password=gitlab_password,
                                        private_token=gitlab_token, api_version=4)
        gitlab_instance.auth()
    except (gitlab.exceptions.GitlabAuthenticationError, gitlab.exceptions.GitlabGetError) as e:
        module.fail_json(msg="Failed to connect to Gitlab server: %s" % to_native(e))
    except (gitlab.exceptions.GitlabHttpError) as e:
        module.fail_json(msg="Failed to connect to Gitlab server: %s. \
            Gitlab remove Session API now that private tokens are removed from user API endpoints since version 10.2." % to_native(e))

    # Set project_path to project_name if it is empty.
    if project_path is None:
        project_path = project_name.replace(" ", "_")

    gitlab_project = GitLabProject(module, gitlab_instance)

    if group_identifier:
        group = findGroup(gitlab_instance, group_identifier)
        if group is None:
            try : # try with user
                namespace = [n for n in gitlab_instance.namespaces.list() if n.full_path == group_identifier][0]
            except IndexError :
                module.fail_json(msg="Failed to create project: group %s doesn't exists" % group_identifier)
        else :
            namespace = gitlab_instance.namespaces.get(group.id)
    else:
        user = gitlab_instance.users.list(username=gitlab_instance.user.username)[0]
        namespace = gitlab_instance.namespaces.get(user.id) # doesn't work
        
    project_exists = gitlab_project.existsProject(namespace, project_path)

    if state == 'absent':
        if project_exists:
            gitlab_project.deleteProject()
            module.exit_json(changed=True, msg="Successfully deleted project %s" % project_name)
        else:
            module.exit_json(changed=False, msg="Project deleted or does not exists")

    if state == 'present':
        (changed, p_branches) = gitlab_project.createOrUpdateProject(project_name, namespace, {
                                                "path": project_path,
                                                "description": project_description,
                                                "issues_enabled": issues_enabled,
                                                "merge_requests_enabled": merge_requests_enabled,
                                                "wiki_enabled": wiki_enabled,
                                                "snippets_enabled": snippets_enabled,
                                                "visibility": visibility,
                                                "import_url": import_url}, branches)
        ret_branches = [p_branch._attrs for p_branch in p_branches]
        if changed :
            module.exit_json(changed=True, project_created=(not project_exists), msg="Successfully created or updated the project %s" % project_name, project=gitlab_project.projectObject._attrs, protected_branches=ret_branches)
        else:
            module.exit_json(changed=False, project_created=(not project_exists), msg="No need to update the project %s" % project_name, project=gitlab_project.projectObject._attrs, protected_branches=ret_branches)





if __name__ == '__main__':
    main()
