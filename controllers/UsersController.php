<?php

class UsersController extends Core\Controller
{
    public function settingsAction($username = null)
    {
        return $this->modifyUser(false, $username);
    }

    public function createAction()
    {
        return $this->modifyUser(true);
    }

    private function modifyUser($create, $username = null)
    {
        $this->kernel->historyDisable();

        /* current user as default */
        $user = $this->session->getUser();

        /* authorize as admin when username is not ours */
        if (!$this->authorize('role:admin') && $username !== null && $username !== $user->get('username')) {
            throw new Exception403();
        }

        if ($username !== null) {
            /* modifying some other user by admin */
            $user = $this->session->getUser($username);
            if (!$user) {
                throw new ErrorException($this->tr('msg/error/user-nonexisting'));
            }
        } else if ($create) {
            /* creating new user */
            $authenticators = $this->kernel->getConfigValue('modules', 'Core\Session', 'authenticators');
            if (count($authenticators) > 1) {
                $usertype = $authenticators[1];
            } else if (count($authenticators) > 0) {
                $usertype = $authenticators[0];
            }

            $user = new $usertype();
            if (!$user) {
                throw new ErrorException('Invalid user type.');
            }
        }

        $params             = $user->getUserdata();
        $params['username'] = $user->get('username');

        if ($this->kernel->method == 'post') {
            $params = $this->input('data');

            /* check email */
            if (!\Core\Validate::email($params['email']) && strlen($params['email']) > 0) {
                $this->kernel->msg('error', $this->tr('msg/error/email-invalid'));
            } else if ($create && strlen($params['username']) < 1) {
                $this->kernel->msg('error', $this->tr('msg/error/username-invalid'));
            } else {
                $ok = true;
                if ($create) {
                    $user = $user->create($params['username']);
                    if (!$user) {
                        $this->kernel->msg('error', $this->tr('msg/error/user-create'));
                        $ok = false;
                    }
                }

                if ($ok) {
                    /* set values */
                    foreach ($params as $key => $value) {
                        $user->set($key, $value);
                    }

                    /* save user data */
                    $user->saveUserdata();

                    if ($create) {
                        $this->kernel->msg('success', $this->tr('msg/success/user-create'));
                        throw new RedirectException($this->route('password_for_user', array('username' => $user->get('username'))), 302);
                    } else {
                        $this->kernel->msg('success', $this->tr('msg/success/user-save-settings'));
                        throw new RedirectException($this->kernel->historyPop(), 302);
                    }
                }
            }
        }

        $params['languages'] = $this->kernel->config['setup']['languages'];
        $params['create']    = $create;

        return $this->display('settings.html', $params);
    }

    public function fakeAction($username)
    {
        $this->session->fakeUser($username);
        $url = $this->getConfigValue('urls', 'account-redirect-fake');
        if (!$url) {
            $url = $this->getConfigValue('urls', 'base');
        }
        throw new RedirectException($url);
    }

    public function searchFormAction($options = null)
    {
        $params              = array();
        $params['formid']    = uniqid();
        $params['users']     = $this->session->getUsers();
        $params['searchmax'] = 5;
        $params['options']   = $options;
        return $this->render('users-search-form.html', $params);
    }
}
