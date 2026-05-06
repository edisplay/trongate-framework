<?php
/**
 * Forgot Password Child Module
 *
 * Handles the forgot-password and password-reset flow.
 * Loaded by the Login parent module. Delegates model operations
 * to the parent Login model.
 */
class Forgot_password extends Trongate {

    /** Secret word matched by resolve_level(), if any. */
    private ?string $matched_secret = null;
    private object $login_model;

    /**
     * Constructor
     *
     * @param string|null $module_name The module name (auto-provided by framework)
     */
    public function __construct(?string $module_name = null) {
        parent::__construct($module_name);
        $this->parent_module = 'login';
    }

    /**
     * Get a reference to the login model.
     *
     * @return object
     */
    private function get_login_model(): object {
        if (!isset($this->login_model)) {
            $this->login_model = $this->login->model;
        }

        return $this->login_model;
    }

    // -----------------------------------------------------------------
    // Forgot Password Form
    // -----------------------------------------------------------------

    /**
     * Display the forgot password form.
     *
     * URL: /login/forgot_password/{user_level_id}
     *
     * @return void
     */
    public function form(): void {
        $model = $this->get_login_model();
        $user_level_id = $this->resolve_level();
        $config = $model->get_level_config($user_level_id);

        $level_slug = $this->matched_secret ?? (string) $user_level_id;
        $data['form_location'] = BASE_URL . 'login/submit_forgot_password/' . $level_slug;
        $data['identifier_label'] = $model->get_identifier_label($user_level_id);
        $data['user_level_id'] = $user_level_id;
        $data['view_module'] = 'login/forgot_password';
        $this->view('forgot_password_form', $data);
    }

    /**
     * Handle forgot password form submission.
     *
     * URL: POST /login/submit_forgot_password/{user_level_id}
     *
     * @return void
     */
    public function submit(): void {
        $model = $this->get_login_model();
        $user_level_id = $this->resolve_level();
        $config = $model->get_level_config($user_level_id);
        $label = $model->get_identifier_label($user_level_id);

        $level_slug = $this->matched_secret ?? (string) $user_level_id;
        $submitted = post('identifier', true);

        if (empty($submitted)) {
            $this->set_flashdata('Please enter your ' . strtolower($label) . '.');
            redirect('login/forgot_password/' . $level_slug);
            return;
        }

        // Find user by identifier (e.g. username) or email
        $user = $model->find_user_lax($submitted, $user_level_id);

        if ($user === false) {
            // Don't reveal whether the account exists
            $this->show_email_sent($user_level_id);
            return;
        }

        // Use the first configured identifier column value for the token
        $ident_columns = $model->get_identifier_columns($user_level_id);
        $identifier = $user->{$ident_columns[0]};

        // Use the email address from the record, or fall back to the submitted value
        $email = $user->email ?? $submitted;

        // Generate reset token
        $token = $model->generate_reset_token($identifier, $user_level_id);

        if ($token === false) {
            // Don't reveal internal errors
            $this->show_email_sent($user_level_id);
            return;
        }

        // Build reset link and send to the user's actual email
        $reset_link = BASE_URL . 'login/reset_password/' . $token;
        $model->send_reset_email($email, $reset_link);

        $this->show_email_sent($user_level_id);
    }

    /**
     * Show the "email sent" confirmation page.
     *
     * @param int $user_level_id
     * @return void
     */
    private function show_email_sent(int $user_level_id): void {
        $data['user_level_id'] = $user_level_id;
        $data['view_module'] = 'login/forgot_password';
        $this->view('email_sent', $data);
    }

    // -----------------------------------------------------------------
    // Reset Password (from email link)
    // -----------------------------------------------------------------

    /**
     * Display the reset password form (from email link).
     *
     * URL: /login/reset_password/{token}
     *
     * @return void
     */
    public function reset(): void {
        $model = $this->get_login_model();
        $token = segment(3);

        if (empty($token) || strlen($token) !== 64) {
            $this->set_flashdata('Invalid or missing reset token.');
            redirect('login');
            return;
        }

        $reset = $model->validate_reset_token($token);

        $data['view_module'] = 'login/forgot_password';

        if ($reset === false) {
            $data['error_message'] = 'This reset link is invalid or has expired.';
            $data['token'] = null;
            $data['form_location'] = '';
            $this->view('reset_password_form', $data);
            return;
        }

        $data['token'] = $token;
        $data['error_message'] = null;
        $data['form_location'] = BASE_URL . 'login/submit_reset_password';
        $this->view('reset_password_form', $data);
    }

    /**
     * Handle the new password submission.
     *
     * URL: POST /login/submit_reset_password
     *
     * @return void
     */
    public function submit_reset(): void {
        $model = $this->get_login_model();
        $token = post('token', true);
        $password = post('password');
        $confirm = post('confirm_password');

        if (empty($token) || strlen($token) !== 64) {
            redirect('login');
            return;
        }

        $data['view_module'] = 'login/forgot_password';
        $reset = $model->validate_reset_token($token);

        if ($reset === false) {
            $data['error_message'] = 'This reset link is invalid or has expired. Please request a new one.';
            $data['token'] = null;
            $data['form_location'] = '';
            $this->view('reset_password_form', $data);
            return;
        }

        // Validate password
        if (empty($password) || strlen($password) < 8) {
            $data['error_message'] = 'Password must be at least 8 characters long.';
            $data['token'] = $token;
            $data['form_location'] = BASE_URL . 'login/submit_reset_password';
            $this->view('reset_password_form', $data);
            return;
        }

        if ($password !== $confirm) {
            $data['error_message'] = 'Passwords do not match.';
            $data['token'] = $token;
            $data['form_location'] = BASE_URL . 'login/submit_reset_password';
            $this->view('reset_password_form', $data);
            return;
        }

        $success = $model->reset_password($token, $password);

        if ($success) {
            $this->view('reset_success', $data);
            return;
        }

        $data['error_message'] = 'Something went wrong. Please try again.';
        $data['token'] = $token;
        $data['form_location'] = BASE_URL . 'login/submit_reset_password';
        $this->view('reset_password_form', $data);
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Determine the target user level from the URL.
     *
     * Delegates to the same logic as the parent login controller.
     *
     * @return int The user level ID
     */
    private function resolve_level(): int {
        $model = $this->get_login_model();
        $levels = $model->get_configured_level_configs();
        $segments = SEGMENTS;

        // Scan for configured secret words in URL segments
        foreach ($levels as $level_id => $config) {
            if (!empty($config['secret_login_word'])) {
                $secret = $config['secret_login_word'];
                foreach ($segments as $seg) {
                    if ($seg === $secret) {
                        $this->matched_secret = $secret;
                        $last = segment(get_num_segments());
                        $level = (int) $last;
                        if ($level > 0 && isset($levels[$level])) {
                            return $level;
                        }
                        return (int) $level_id;
                    }
                }
            }
        }

        // Check if any level has a secret configured
        foreach ($levels as $config) {
            if (!empty($config['secret_login_word'])) {
                show_404();
                die();
            }
        }

        // No secrets — fall back to numeric segment
        $segment = segment(3, 'int');

        if ($segment > 0 && isset($levels[$segment])) {
            return $segment;
        }

        show_404();
        die();
    }

    /**
     * Set a flashdata error message.
     *
     * @param string $msg
     * @return void
     */
    private function set_flashdata(string $msg): void {
        set_flashdata('<div class="validation-errors"><p>' . out($msg) . '</p></div>');
    }

}
