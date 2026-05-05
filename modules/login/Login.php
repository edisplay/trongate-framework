<?php
/**
 * Login Module
 *
 * Portable, configurable authentication module for Trongate v2.
 * Supports multiple user levels, each with its own target table,
 * field mappings, and view files.
 */
class Login extends Trongate {

    /**
     * Constructor
     *
     * @param string|null $module_name The module name (auto-provided by framework)
     */
    public function __construct(?string $module_name = null) {
        parent::__construct($module_name);
    }

    /**
     * Determine the target user level from the URL segment.
     *
     * Falls back to the configured default user level.
     *
     * @return int The user level ID
     */
    private function resolve_level(?int $override = null): int {

        if ($override !== null) {
            return $override;
        }

        // When method is in URL (e.g., /login/login/2), level is segment(3)
        // When no method in URL (/login), segment(2) is empty or non-numeric
        // When called from index(), segment(3) may hold the level
        $segment = segment(3, 'int');

        if ($segment > 0) {
            return $segment;
        }

        return (int) ($this->model->get_global_config('default_user_level') ?? 2);
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    /**
     * Default route - shows login form.
     *
     * @return void
     */
    public function index(): void {
        $this->login();
    }

    /**
     * Display the login form for a given user level.
     *
     * URL: /login/{user_level_id}
     *
     * @return void
     */
    public function login(): void {
        $user_level_id = $this->resolve_level();

        // Redirect if already logged in
        $token = $this->trongate_tokens->attempt_get_valid_token($user_level_id);

        if ($token !== false) {
            $config = $this->model->get_level_config($user_level_id);
            redirect($config['redirect_on_success']);
            return;
        }

        // Destroy lingering tokens
        $this->trongate_tokens->destroy();

        $config = $this->model->get_level_config($user_level_id);

        $data['form_location'] = BASE_URL . 'login/submit_login/' . $user_level_id;
        $data['user_level_id'] = $user_level_id;
        $data['fields'] = $config['fields'];
        $data['identifier_label'] = $this->model->get_identifier_label($user_level_id);
        $data['allow_remember'] = $config['allow_remember'] ?? 0;
        $data['view_module'] = $this->module_name;
        $data['view_file'] = $config['view_file'];
        $data['forgot_password_url'] = 'login/forgot_password/' . $user_level_id;

        // Determine which view file to use
        $view_file = $config['view_file'] ?? 'login_default';

        $this->view($view_file, $data);
    }

    /**
     * Handle login form submission.
     *
     * URL: POST /login/submit_login/{user_level_id}
     *
     * @return void
     */
    public function submit_login(): void {
        $user_level_id = $this->resolve_level(segment(3, 'int'));
        $config = $this->model->get_level_config($user_level_id);
        $ident_label = strtolower($this->model->get_identifier_label($user_level_id));

        // Rate limiting check (before validation)
        $this->model->remove_expired_restrictions($user_level_id);

        if (!$this->model->is_login_allowed(post('identifier', true), $user_level_id)) {
            redirect('login/not_allowed/' . $user_level_id);
            return;
        }

        // Set validation rules with custom credentials callback
        $this->validation->set_rules('identifier', $ident_label, 'required|callback_credentials_valid');
        $this->validation->set_rules('password', 'password', 'required');

        if ($this->validation->run() === true) {
            // Credentials are valid — log the user in
            $identifier = post('identifier', true);
            $remember = (int) (bool) post('remember');
            $token = $this->model->log_user_in($identifier, $user_level_id, $remember);

            if ($token === false) {
                http_response_code(500);
                $msg = 'Authentication succeeded but token generation failed. ';
                $msg .= 'Ensure the target table has a valid ' . $config['user_ref_field'] . '.';
                echo (ENV === 'dev') ? $msg : 'An internal error occurred.';
                die();
            }

            $this->model->clear_failed_attempts($identifier, $user_level_id);
            redirect($config['redirect_on_success']);
        }

        // Validation failed — record the attempt
        $this->model->record_failed_attempt(post('identifier', true), $user_level_id);

        // Check if the user is now rate-limited
        if (!$this->model->is_login_allowed(post('identifier', true), $user_level_id)) {
            redirect('login/not_allowed/' . $user_level_id);
            return;
        }

        // Redisplay form with validation errors
        $this->login();
    }

    /**
     * Display rate-limited page.
     *
     * URL: /login/not_allowed/{user_level_id}
     *
     * @return void
     */
    public function not_allowed(): void {
        $user_level_id = $this->resolve_level();
        $block_duration = $this->model->get_global_config('block_duration') ?? 900;

        $data['block_duration'] = (int) ($block_duration / 60);
        $data['user_level_id'] = $user_level_id;
        $data['view_module'] = $this->module_name;
        $data['view_file'] = 'not_allowed';

        $this->view('not_allowed', $data);
    }

    /**
     * Unlock all rate-limited users (dev mode only).
     *
     * URL: /login/unlock
     *
     * @return void
     */
    public function unlock(): void {
        if (ENV !== 'dev') {
            http_response_code(403);
            echo 'This endpoint is only available in development mode.';
            die();
        }

        $this->model->unlock_all();

        echo 'All rate-limit restrictions have been cleared.';
    }

    /**
     * Log the user out.
     *
     * @return void
     */
    public function logout(): void {
        $this->trongate_tokens->destroy();
        redirect('login');
    }

    /**
     * Check if a user is logged in with the given user level.
     *
     * @param int|null $user_level_id The user level to check, or null for any
     * @return string|bool True if logged in, error message otherwise
     */
    public function is_logged_in(?int $user_level_id = null): string|bool {
        if ($user_level_id !== null) {
            $token = $this->trongate_tokens->attempt_get_valid_token($user_level_id);
        } else {
            $token = $this->trongate_tokens->attempt_get_valid_token();
        }

        if ($token !== false) {
            return true;
        }

        return 'You must be logged in to access this page.';
    }

    // -----------------------------------------------------------------
    // Forgot Password (delegates to child module)
    // -----------------------------------------------------------------

    /**
     * Display the forgot password form.
     *
     * URL: /login/forgot_password/{user_level_id}
     *
     * @return void
     */
    public function forgot_password(): void {
        $this->module('login-forgot_password');
        $this->forgot_password->form();
    }

    /**
     * Handle forgot password form submission.
     *
     * URL: POST /login/submit_forgot_password/{user_level_id}
     *
     * @return void
     */
    public function submit_forgot_password(): void {
        $this->module('login-forgot_password');
        $this->forgot_password->submit();
    }

    /**
     * Display the reset password form (from email link).
     *
     * URL: /login/reset_password/{token}
     *
     * @return void
     */
    public function reset_password(): void {
        $this->module('login-forgot_password');
        $this->forgot_password->reset();
    }

    /**
     * Handle the new password submission.
     *
     * URL: POST /login/submit_reset_password
     *
     * @return void
     */
    public function submit_reset_password(): void {
        $this->module('login-forgot_password');
        $this->forgot_password->submit_reset();
    }

    // -----------------------------------------------------------------
    // Custom Validation Callback
    // -----------------------------------------------------------------

    /**
     * Custom validation callback that checks credentials against the database.
     *
     * Invoked by the validation module as part of the 'identifier' field rules.
     * Returns true if credentials are valid, or an error string otherwise.
     *
     * @param string $identifier The submitted identifier (pre-cleaned by post()).
     * @return string|bool True if valid, error message string if invalid.
     */
    public function credentials_valid(string $identifier): string|bool {
        block_url('login/credentials_valid');

        $user_level_id = $this->resolve_level(segment(3, 'int'));
        $password = post('password');  // Raw value — do not clean or trim

        $valid = $this->model->validate_credentials($identifier, $password, $user_level_id);

        if ($valid === true) {
            return true;
        }

        return 'The {label} and/or password you entered is incorrect.';
    }

}
