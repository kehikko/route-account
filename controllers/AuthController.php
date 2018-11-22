<?php

class AuthController extends Core\Controller
{
    public function loginAction()
    {
        /* do not puth authentication entries into history */
        $this->kernel->historyDisable();

        if ($this->session->get('username')) {
            throw new RedirectException($this->route('logout'), 302);
        }

        $params                  = array();
        $params['last_username'] = '';

        if ($this->kernel->method == 'post') {
            $username = $this->input('username');
            $password = $this->input('password');

            $ok = $this->session->authenticate($username, $password);
            if ($ok) {
                throw new RedirectException($this->kernel->historyPop(), 302);
            }

            $this->kernel->msg('error', 'Login failed.');
            $params['last_username'] = $username;
        }
        
        throw new \RedirectException(\kernel::expand('{url:login}'), 302);
    }

    public function logoutAction()
    {
        /* do not puth authentication entries into history */
        $this->kernel->historyDisable();

        if ($this->session->get('username')) {
            $this->session->destroy();
        }
        throw new \RedirectException(\kernel::expand('{url:base}'), 302);
    }

    public function passwordAction($username = false)
    {
        /* do not puth authentication entries into history */
        $this->kernel->historyDisable();

        $params             = array();
        $params['username'] = false;

        /* change password if request was post */
        if ($this->kernel->method == 'post') {
            $user          = $this->session->getUser();
            $password_old  = $this->input('password-old');
            $password_new1 = $this->input('password-new1');
            $password_new2 = $this->input('password-new2');

            /* if user has role:admin (or role:root for that matter)
             * it is possible to change passwords for other users.
             */
            if ($this->session->authorize('role:admin') && $username) {
                $users = $this->session->getUsers();
                if (!isset($users[$username])) {
                    throw new Exception('User does not exist: ' . $username);
                }
                $user = $users[$username];
            }

            if ($password_new1 != $password_new2) {
                $this->kernel->msg('error', 'New passwords do not match.');
            } else if (!$user->checkPassword($password_old) && (!$this->session->authorize('role:admin') || $this->session->get('username') == $user->get('username'))) {
                $this->kernel->msg('error', 'Invalid password.');
            } else if (strlen($password_new1) < 8) {
                $this->kernel->msg('error', 'Password must be atleast 8 characters.');
            } else {
                $user->setPassword($password_new2);
                $this->kernel->msg('success', 'Password changed!');
                throw new RedirectException($this->kernel->historyPop(), 302);
            }
        }

        /* if user has role:admin (or role:root for that matter)
         * it is possible to change passwords for other users.
         */
        if ($this->session->authorize('role:admin') && $username) {
            $params['username'] = $username;
        }

        return $this->render('password.html', $params);
    }

    public function loginFormAction()
    {
        return $this->render('login-form.html');
    }
}
