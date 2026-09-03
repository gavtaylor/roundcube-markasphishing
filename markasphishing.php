<?php

/**
 * markasphishing
 *
 * A plugin that adds a "Report Phishing" button to the mailbox toolbar
 * (and, via the contextmenu plugin if installed, a right-click entry) to
 * forward the selected message as a phishing report -- to the abuse desk
 * of the provider that sent it and to configurable reporting authorities --
 * then move, delete, or leave the original message according to the
 * reporting user's preference.
 *
 * Architecturally modelled on Roundcube's own core `markasjunk` plugin
 * for consistency with the rest of the ecosystem; written independently.
 *
 * @author Gavin Taylor
 *
 * Copyright (C) Gavin Taylor
 *
 * This program is a Roundcube (https://roundcube.net) plugin.
 * For more information see README.md.
 * For configuration see config.inc.php.dist.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
 */
class markasphishing extends rcube_plugin
{
    public $task = 'mail|settings';

    private const TABLE = 'markasphishing_recipients';
    private const REPORTED_TABLE = 'markasphishing_reported';
    private const LOG_TABLE = 'markasphishing_report_log';
    private const VERSION_KEY = 'markasphishing-schema-version';
    private const SCHEMA_VERSION = '2026081002';
    private const SCHEMA_VERSION_DOMAIN_CONSOLIDATION = '2026080900';
    private const SCHEMA_VERSION_DEDUPE_TABLE = '2026081000';
    private const SCHEMA_VERSION_REPORT_LOG = '2026081001';

    private $rcube;
    private $schema_checked = false;
    private $editing_row = null;

    #[\Override]
    public function init()
    {
        $this->rcube = rcmail::get_instance();
        $this->load_config();

        $this->register_action('plugin.markasphishing.report', [$this, 'report_message']);
        $this->register_action('plugin.markasphishing', [$this, 'settings_page']);
        $this->register_action('plugin.markasphishing.save', [$this, 'save']);
        $this->register_action('plugin.markasphishing.directory-delete', [$this, 'directory_delete']);
        $this->register_action('plugin.markasphishing.directory-add', [$this, 'directory_add_page']);
        $this->register_action('plugin.markasphishing.directory-add-save', [$this, 'directory_add_save']);

        if ($this->rcube->task === 'mail') {
            $action = $this->rcube->action;

            if ($action === '' || $action === 'show') {
                $this->add_texts('localization', true);
                $this->include_script('markasphishing.js');
                $this->include_stylesheet($this->local_skin_path() . '/markasphishing.css');
                $this->rcube->output->add_label('markasphishing.confirmreport');

                if ($this->rcube->config->get('markasphishing_toolbar', true)) {
                    // add the button to the main toolbar
                    $this->add_button([
                        'command' => 'plugin.markasphishing.report',
                        'type' => 'link',
                        'class' => 'button buttonPas phishing disabled',
                        'classact' => 'button phishing',
                        'classsel' => 'button phishing pressed',
                        'title' => 'markasphishing.buttonreport',
                        'innerclass' => 'inner',
                        'label' => 'markasphishing.report',
                    ], 'toolbar');
                } else {
                    // add the button to the mark message menu
                    $this->add_button([
                        'command' => 'plugin.markasphishing.report',
                        'type' => 'link-menuitem',
                        'label' => 'markasphishing.report',
                        'id' => 'markasphishing',
                        'class' => 'icon phishing disabled',
                        'classact' => 'icon phishing active',
                        'innerclass' => 'icon phishing',
                    ], 'markmenu');
                }
            }
        } elseif ($this->rcube->task === 'settings') {
            // settings_actions fires on every settings page (to build the
            // nav), not just when our own tab is open, so texts must be
            // loaded unconditionally here rather than deferred to settings_page()
            $this->add_texts('localization', true);
            $this->add_hook('settings_actions', [$this, 'settings_actions']);

            // Both must be loaded unconditionally here, not deferred to
            // settings_page(): the settings-menu sidebar (and its
            // markasphishing icon override) is rendered by core on every
            // settings tab, not just ours, and this script is loaded via
            // Roundcube's normal script-inclusion path (not an inline
            // <script> in the settings_form() output) since that markup
            // can be inserted by Roundcube's own AJAX navigation, which
            // doesn't execute embedded <script> tags
            $this->include_script('markasphishing.js');
            $this->include_stylesheet($this->local_skin_path() . '/markasphishing.css');
        }
    }

    /**
     * Handler for plugin.markasphishing.report: build and send a phishing
     * report for each selected message, then apply the reporting user's
     * configured post-report action to the originals.
     */
    public function report_message()
    {
        $this->add_texts('localization', true);

        $uids = rcube_utils::get_input_value('_uid', rcube_utils::INPUT_POST);
        $mbox_name = rcube_utils::get_input_string('_mbox', rcube_utils::INPUT_POST);
        $messageset = rcmail_action::get_uids($uids, $mbox_name, $multifolder);

        $storage = $this->rcube->get_storage();

        // get_uids() leaves '*' (select-all in a single folder) unexpanded
        // since it's meaningful directly to IMAP flag/move commands -- but
        // we need concrete UIDs to build one report per message
        if ($uids === '*' && !$multifolder) {
            $messageset = [$mbox_name => $storage->index($mbox_name)->get()];
        }

        $reported_uids = [];
        $prefs = $this->_get_user_prefs();
        $any_sent = false;
        $any_skipped = false;
        $sent_total = 0;
        $recipients_total = 0;

        foreach ($messageset as $source_mbox => $mbox_uids) {
            $storage->set_folder($source_mbox);

            foreach ((array) $mbox_uids as $uid) {
                $result = $this->_report_one($uid, $source_mbox);

                if ($result['status'] === 'failed') {
                    continue;
                }

                $reported_uids[] = $uid;

                if (!empty($prefs['mark_read'])) {
                    $storage->set_flag($uid, 'SEEN', $source_mbox);
                }

                if ($result['status'] === 'skipped') {
                    $any_skipped = true;
                } else {
                    $any_sent = true;
                    $sent_total += $result['sent'];
                    $recipients_total += $result['total'];
                }
            }
        }

        if (!empty($reported_uids)) {
            if ($prefs['action'] === 'folder') {
                $this->_ensure_folder($prefs['folder']);
                $this->rcube->output->command('markasphishing_move', $prefs['folder'], false, $reported_uids);
            } elseif ($prefs['action'] === 'delete') {
                $this->rcube->output->command('markasphishing_move', null, true, $reported_uids);
            } else {
                $this->rcube->output->command('command', 'list', $mbox_name);
            }

            if ($any_sent && $sent_total < $recipients_total) {
                $this->rcube->output->command('display_message', $this->gettext([
                    'name' => 'reportpartial',
                    'vars' => ['failed' => $recipients_total - $sent_total, 'total' => $recipients_total],
                ]), 'warning');
            } elseif (!$any_sent && $any_skipped) {
                $this->rcube->output->command('display_message', $this->gettext('reportskipped'), 'notice');
            } else {
                $this->rcube->output->command('display_message', $this->gettext('reportedasphishing'), 'confirmation');
            }
        } else {
            $this->rcube->output->command('display_message', $this->gettext('reportfailed'), 'error');
        }

        $this->rcube->output->send();
    }

    /**
     * Adds the "Phishing Reporting" tab to Settings.
     */
    public function settings_actions($args)
    {
        $args['actions'][] = [
            'action' => 'plugin.markasphishing',
            'class' => 'markasphishing',
            'label' => 'settingstitle',
            'title' => 'settingstitle',
            'domain' => 'markasphishing',
        ];

        return $args;
    }

    /**
     * Renders the settings page (preferences + report directory).
     */
    public function settings_page()
    {
        $this->add_texts('localization', true);
        $this->_ensure_schema();
        $this->register_handler('plugin.body', [$this, 'settings_form']);
        $this->rcube->output->set_pagetitle($this->gettext('settingstitle'));
        $this->rcube->output->send('plugin');
    }

    /**
     * Single save handler for the whole settings page: the logged-in
     * user's preferences (everyone), plus the report directory's enabled
     * states and any new entry (admins only). One form, one button.
     */
    public function save()
    {
        $this->add_texts('localization', true);

        $action = rcube_utils::get_input_string('_post_action', rcube_utils::INPUT_POST);
        if (!in_array($action, ['folder', 'delete', 'leave'], true)) {
            $action = 'folder';
        }

        $folder = rcube_utils::get_input_string('_folder', rcube_utils::INPUT_POST);

        $this->rcube->user->save_prefs([
            'markasphishing' => [
                'action' => $action,
                'folder' => $folder !== '' ? $folder : 'Phishing',
                'mark_read' => rcube_utils::get_input_string('_mark_read', rcube_utils::INPUT_POST) === '1',
            ],
        ]);

        if ($this->_is_admin()) {
            $this->_ensure_schema();
            $db = $this->rcube->get_dbh();
            $table = $db->table_name(self::TABLE);

            $ids = (array) rcube_utils::get_input_value('_ids', rcube_utils::INPUT_POST);
            $enabled_ids = (array) rcube_utils::get_input_value('_enabled', rcube_utils::INPUT_POST);

            foreach ($ids as $id) {
                $enabled = in_array($id, $enabled_ids) ? 1 : 0;
                $db->query("UPDATE {$table} SET enabled = ? WHERE id = ?", $enabled, (int) $id);
            }
        }

        $this->rcube->output->command('display_message', $this->gettext('prefssaved'), 'confirmation');
        $this->rcube->overwrite_action('plugin.markasphishing');
        $this->settings_page();
    }

    /**
     * Admin-only: deletes a single report directory entry.
     */
    public function directory_delete()
    {
        $this->add_texts('localization', true);
        $this->_ensure_schema();

        if ($this->_is_admin()) {
            $id = (int) rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);
            $db = $this->rcube->get_dbh();
            $db->query('DELETE FROM ' . $db->table_name(self::TABLE) . ' WHERE id = ?', $id);
            $this->rcube->output->command('display_message', $this->gettext('directorydeleted'), 'confirmation');
        } else {
            $this->rcube->output->command('display_message', $this->gettext('notadmin'), 'error');
        }

        $this->rcube->overwrite_action('plugin.markasphishing');
        $this->settings_page();
    }

    /**
     * Admin-only: renders the standalone add/edit-entry page, kept off the
     * main settings page since it's not something done often. Same form
     * either way -- editing is just this page pre-filled from an existing
     * row, keyed by a hidden _id field the save handler checks for.
     */
    public function directory_add_page()
    {
        $this->add_texts('localization', true);

        if (!$this->_is_admin()) {
            $this->rcube->output->command('display_message', $this->gettext('notadmin'), 'error');
            $this->rcube->overwrite_action('plugin.markasphishing');
            $this->settings_page();
            return;
        }

        $id = (int) rcube_utils::get_input_value('_id', rcube_utils::INPUT_GET);

        if ($id) {
            $this->_ensure_schema();
            $db = $this->rcube->get_dbh();
            $result = $db->query('SELECT * FROM ' . $db->table_name(self::TABLE) . ' WHERE id = ?', $id);
            $this->editing_row = $db->fetch_assoc($result) ?: null;
        }

        $this->register_handler('plugin.body', [$this, 'directory_add_form']);
        $this->rcube->output->set_pagetitle($this->gettext($this->editing_row ? 'editheading' : 'addheading'));
        $this->rcube->output->send('plugin');
    }

    /**
     * Admin-only: inserts a new report directory entry, or updates an
     * existing one if the form's hidden _id field is set, then returns to
     * the main settings page.
     */
    public function directory_add_save()
    {
        $this->add_texts('localization', true);
        $this->_ensure_schema();

        if ($this->_is_admin()) {
            $id = (int) rcube_utils::get_input_value('_id', rcube_utils::INPUT_POST);
            $name = rcube_utils::get_input_string('_new_name', rcube_utils::INPUT_POST);
            $address = rcube_utils::get_input_string('_new_address', rcube_utils::INPUT_POST);
            $type = rcube_utils::get_input_string('_new_type', rcube_utils::INPUT_POST) === 'authority' ? 'authority' : 'provider';
            $raw_domain = rcube_utils::get_input_string('_new_domain', rcube_utils::INPUT_POST);
            $description = rcube_utils::get_input_string('_new_description', rcube_utils::INPUT_POST);

            if ($name !== '' && $address !== '') {
                $domain = $type === 'provider' ? $this->_normalize_domain_list($raw_domain) : null;

                if ($type === 'authority' || $domain !== '') {
                    $db = $this->rcube->get_dbh();
                    $table = $db->table_name(self::TABLE);

                    if ($id) {
                        $db->query(
                            "UPDATE {$table} SET type = ?, domain = ?, name = ?, report_address = ?, description = ? WHERE id = ?",
                            $type,
                            $domain,
                            $name,
                            $address,
                            $description !== '' ? $description : null,
                            $id
                        );
                    } else {
                        $db->query(
                            "INSERT INTO {$table} (type, domain, name, report_address, enabled, is_default, description) VALUES (?, ?, ?, ?, 1, 0, ?)",
                            $type,
                            $domain,
                            $name,
                            $address,
                            $description !== '' ? $description : null
                        );
                    }

                    $this->rcube->output->command('display_message', $this->gettext('directorysaved'), 'confirmation');
                } else {
                    // re-render the form with whatever was submitted (not a
                    // fresh DB fetch) so a validation failure doesn't lose
                    // the user's in-progress edit
                    $this->editing_row = [
                        'id' => $id,
                        'type' => $type,
                        'domain' => $raw_domain,
                        'name' => $name,
                        'report_address' => $address,
                        'description' => $description,
                    ];

                    $this->rcube->output->command('display_message', $this->gettext('directorydomainrequired'), 'error');
                    $this->rcube->overwrite_action('plugin.markasphishing.directory-add');
                    $this->register_handler('plugin.body', [$this, 'directory_add_form']);
                    $this->rcube->output->set_pagetitle($this->gettext($id ? 'editheading' : 'addheading'));
                    $this->rcube->output->send('plugin');
                    return;
                }
            }
        } else {
            $this->rcube->output->command('display_message', $this->gettext('notadmin'), 'error');
        }

        $this->rcube->overwrite_action('plugin.markasphishing');
        $this->settings_page();
    }

    /**
     * Renders the plugin.body handler: one form covering both preferences
     * and the report directory, with a single sticky Save button. Per-row
     * delete triggers post to their own hidden forms via JS (markasphishing.js)
     * since they can't live inside the main form -- HTML forms don't nest.
     */
    public function settings_form()
    {
        $this->include_stylesheet($this->local_skin_path() . '/markasphishing.css');

        // a real <button>, not <input type=submit> -- input elements can't
        // render the ::before checkmark icon core's own Save buttons use
        // (generated content doesn't apply to replaced elements), so this
        // used to render as a plain unstyled rectangle
        $submit = html::tag('button', ['type' => 'submit', 'class' => 'button mainaction submit'], rcube::Q($this->gettext('save')));

        $form = $this->rcube->output->form_tag([
            'id' => 'markasphishing-form',
            'method' => 'post',
            'action' => './?_task=settings&_action=plugin.markasphishing.save',
        ], $this->_prefs_fields_html() . $this->_directory_fields_html()
            . html::div(['class' => 'markasphishing-savebar'], $submit));

        return html::div(['class' => 'markasphishing-settings'], $form);
    }

    /**
     * Renders the plugin.body handler for the standalone add/edit-entry
     * page. Pre-filled from $this->editing_row when editing (set by
     * directory_add_page() from the DB, or by directory_add_save() from
     * the just-submitted values if validation failed).
     */
    public function directory_add_form()
    {
        $this->include_stylesheet($this->local_skin_path() . '/markasphishing.css');

        $row = $this->editing_row;

        $type_select = new html_select(['name' => '_new_type']);
        $type_select->add($this->gettext('typeprovider'), 'provider');
        $type_select->add($this->gettext('typeauthority'), 'authority');

        $add_table = new html_table(['cols' => 2, 'class' => 'propform']);
        $add_table->add('title', rcube::Q($this->gettext('coltype')));
        $add_table->add(null, $type_select->show($row['type'] ?? 'provider'));
        $add_table->add('title', rcube::Q($this->gettext('colname')));
        $add_table->add(null, (new html_inputfield(['name' => '_new_name', 'size' => 30, 'value' => $row['name'] ?? '']))->show());
        $add_table->add('title', rcube::Q($this->gettext('coldomain'))
            . html::tag('small', ['class' => 'markasphishing-hint'], rcube::Q($this->gettext('domainhint'))));
        $add_table->add(null, (new html_inputfield(['name' => '_new_domain', 'size' => 30, 'value' => $row['domain'] ?? '']))->show());
        $add_table->add('title', rcube::Q($this->gettext('coladdress')));
        $add_table->add(null, (new html_inputfield(['name' => '_new_address', 'size' => 30, 'value' => $row['report_address'] ?? '']))->show());
        $add_table->add('title', rcube::Q($this->gettext('coldescription')));
        $add_table->add(null, (new html_inputfield(['name' => '_new_description', 'size' => 30, 'value' => $row['description'] ?? '']))->show());

        $submit = html::tag('button', ['type' => 'submit', 'class' => 'button mainaction submit'], rcube::Q($this->gettext('save')));
        $cancel = html::a(['href' => './?_task=settings&_action=plugin.markasphishing', 'class' => 'button'], rcube::Q($this->gettext('cancel')));
        $hidden_id = !empty($row['id']) ? '<input type="hidden" name="_id" value="' . (int) $row['id'] . '">' : '';

        $form = $this->rcube->output->form_tag([
            'id' => 'markasphishing-add-form',
            'method' => 'post',
            'action' => './?_task=settings&_action=plugin.markasphishing.directory-add-save',
        ], $hidden_id . $add_table->show() . html::p(['class' => 'formbuttons footerleft'], $submit . $cancel));

        return html::div(['class' => 'markasphishing-settings'],
            html::tag('h3', null, rcube::Q($this->gettext($row ? 'editheading' : 'addheading'))) . $form);
    }

    /**
     * Returns ['status' => 'sent'|'skipped'|'failed', 'sent' => int, 'total' => int].
     * 'skipped' means this exact Message-ID was already reported (by any
     * user on this instance) and nothing was sent this time; 'failed' means
     * no recipients could be found at all, or every send attempt failed.
     */
    private function _report_one($uid, $mbox)
    {
        $message = new rcube_message($uid, $mbox);

        if (empty($message->headers)) {
            return ['status' => 'failed', 'sent' => 0, 'total' => 0];
        }

        $message_id = (string) $message->headers->messageID;

        // opportunistic cleanup, not gated on anything else below -- see
        // _gc_reported() for why this is probabilistic rather than cron-based
        $this->_gc_reported();

        if ($message_id !== '' && $this->_already_reported($message_id)) {
            return ['status' => 'skipped', 'sent' => 0, 'total' => 0];
        }

        $from_domain = $this->_extract_domain((string) $message->headers->from);
        $envelope_domain = $this->_extract_envelope_domain($message);

        $recipients = $this->_lookup_provider_recipients($from_domain);

        // From: is exactly what phishing spoofs, so a match there doesn't
        // mean the envelope/authenticated domain was ever considered --
        // look that up too when it differs, so the actual sending
        // provider (not just whichever brand got impersonated) also gets
        // an RFC 2142 fallback address
        if ($envelope_domain !== '' && $envelope_domain !== $from_domain) {
            $recipients = array_merge($recipients, $this->_lookup_provider_recipients($envelope_domain));
        }

        $recipients = array_merge($recipients, $this->_lookup_authority_recipients());
        $recipients = array_values(array_unique(array_map('mb_strtolower', $recipients)));

        if (empty($recipients)) {
            return ['status' => 'failed', 'sent' => 0, 'total' => 0];
        }

        $result = $this->_send_report($uid, $message, $recipients);

        if ($result['sent'] === 0) {
            return ['status' => 'failed', 'sent' => 0, 'total' => $result['total']];
        }

        if ($message_id !== '') {
            $this->_mark_reported($message_id);
        }

        return ['status' => 'sent', 'sent' => $result['sent'], 'total' => $result['total']];
    }

    private function _extract_domain($from)
    {
        if (preg_match('/@([a-z0-9.-]+\.[a-z]{2,})/i', $from, $matches)) {
            return mb_strtolower($matches[1]);
        }

        return '';
    }

    /**
     * Best-effort source for the domain that actually sent the message,
     * as opposed to _extract_domain()'s From: header -- exactly the field
     * phishing mail spoofs. Not every mail server stamps these headers
     * consistently, so an empty result here is expected and not an error.
     */
    private function _extract_envelope_domain($message)
    {
        $others = $message->headers->others ?? [];

        $return_path = $others['return-path'] ?? '';
        $return_path = is_array($return_path) ? reset($return_path) : $return_path;
        $domain = $this->_extract_domain((string) $return_path);

        if ($domain !== '') {
            return $domain;
        }

        foreach ((array) ($others['authentication-results'] ?? []) as $header_value) {
            foreach (explode(';', (string) $header_value) as $segment) {
                if (preg_match('/\bdkim=pass\b/i', $segment)
                    && preg_match('/header\.d=([a-z0-9.-]+\.[a-z]{2,})/i', $segment, $matches)
                ) {
                    return mb_strtolower($matches[1]);
                }
            }
        }

        return '';
    }

    /**
     * One provider row can own several domains (e.g. Microsoft: outlook.com,
     * hotmail.com, live.com, msn.com), stored as a comma-separated list.
     */
    private function _normalize_domain_list($raw)
    {
        $domains = array_filter(array_map('trim', explode(',', mb_strtolower((string) $raw))));

        return implode(', ', array_unique($domains));
    }

    private function _lookup_provider_recipients($domain)
    {
        if ($domain === '') {
            return [];
        }

        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::TABLE);
        $recipients = [];

        // domain is a comma-separated list per row (one row per provider,
        // not per domain), so matching happens here rather than in the query
        $result = $db->query("SELECT domain, report_address FROM {$table} WHERE type = 'provider' AND enabled = 1");
        while ($row = $db->fetch_assoc($result)) {
            $row_domains = array_map('trim', explode(',', (string) $row['domain']));
            if (in_array($domain, $row_domains, true)) {
                $recipients[] = $row['report_address'];
            }
        }

        if (empty($recipients) && $this->rcube->config->get('markasphishing_rfc2142_fallback', true)) {
            $recipients[] = 'abuse@' . $domain;
        }

        return $recipients;
    }

    private function _lookup_authority_recipients()
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::TABLE);
        $recipients = [];

        $result = $db->query("SELECT report_address FROM {$table} WHERE type = 'authority' AND enabled = 1");
        while ($row = $db->fetch_assoc($result)) {
            $recipients[] = $row['report_address'];
        }

        return $recipients;
    }

    private function _already_reported($message_id)
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::REPORTED_TABLE);
        $result = $db->query("SELECT 1 FROM {$table} WHERE message_id = ?", $message_id);

        return (bool) $db->fetch_assoc($result);
    }

    private function _mark_reported($message_id)
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::REPORTED_TABLE);

        // INSERT IGNORE: a race between two near-simultaneous reports of
        // the same message hitting the primary key is fine to just drop --
        // the outcome (message_id now recorded) is the same either way
        $db->query("INSERT IGNORE INTO {$table} (message_id, reported_at) VALUES (?, {$db->now()})", $message_id);
    }

    /**
     * Records one send attempt (success or failure) per recipient, so stats
     * can show which providers/authorities actually get reported to, how
     * often deliveries fail, and which mailbox on this instance is on the
     * receiving end of the phishing -- detail markasphishing_reported
     * doesn't carry, since that table exists purely for the dedupe check
     * above. Username is the reporting user's, i.e. whichever mailbox
     * actually received the phishing message, not who it was sent to.
     */
    private function _log_report_attempt($message_id, $recipient, $success)
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::LOG_TABLE);

        $db->query(
            "INSERT INTO {$table} (message_id, recipient, username, success, sent_at) VALUES (?, ?, ?, ?, {$db->now()})",
            $message_id,
            $recipient,
            $this->rcube->user->get_username(),
            $success ? 1 : 0
        );
    }

    /**
     * Probabilistic opportunistic cleanup, the same pattern PHP's own
     * session GC uses (session.gc_probability/session.gc_divisor) --
     * Roundcube core gives plugins no hook into its own gc.sh (checked:
     * rcube::gc() only does cache/session/temp-dir cleanup), so this runs
     * inline on a small fraction of report attempts instead. No cron
     * needed, works the moment the plugin is used at all. Covers both
     * markasphishing_reported and markasphishing_report_log, sharing the
     * same retention window.
     */
    private function _gc_reported()
    {
        if (random_int(1, 50) !== 1) {
            return;
        }

        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $days = max(1, (int) $this->rcube->config->get('markasphishing_dedupe_retention_days', 90));
        $cutoff = $db->now(-$days * 86400);

        $db->query('DELETE FROM ' . $db->table_name(self::REPORTED_TABLE) . " WHERE reported_at < {$cutoff}");
        $db->query('DELETE FROM ' . $db->table_name(self::LOG_TABLE) . " WHERE sent_at < {$cutoff}");
    }

    /**
     * Sends one separate email per recipient rather than a single email
     * with the rest Bcc'd. We haven't verified how any of these abuse
     * desks' intake systems handle a multi-recipient forward, so this
     * doesn't assume they treat it the same as an individual report.
     */
    private function _send_report($uid, $message, array $recipients)
    {
        $identity = $this->rcube->user->get_identity();
        $from = $identity['email'];
        $from_string = !empty($identity['name']) ? format_email_recipient($from, $identity['name']) : $from;

        $temp_dir = unslashify($this->rcube->config->get('temp_dir'));
        $message_file = tempnam($temp_dir, 'rcm');
        $sent_count = 0;
        $message_id = (string) $message->headers->messageID;

        if ($fp = fopen($message_file, 'w')) {
            $this->rcube->get_storage()->get_raw_body($uid, $fp);
            fclose($fp);

            $orig_subject = $message->get_header('subject');

            $attachment = [
                'name' => $this->_safe_attachment_name($orig_subject),
                'mimetype' => 'message/rfc822',
                'path' => $message_file,
                'size' => filesize($message_file),
                'charset' => $message->headers->charset,
            ];

            $folding = (int) $this->rcube->config->get('mime_param_folding');
            $debug = $this->rcube->config->get('markasphishing_debug', false);
            $last = array_key_last($recipients);

            foreach ($recipients as $i => $to) {
                $headers = [
                    'Date' => $this->rcube->user_date(),
                    'From' => $from_string,
                    'To' => $to,
                    'Subject' => $this->gettext(['name' => 'reportsubject', 'vars' => ['subject' => $orig_subject]]),
                    'Message-ID' => $this->rcube->gen_message_id($from),
                    'X-Sender' => $from,
                ];

                $OUTPUT = $this->rcube->output;
                $SENDMAIL = new rcmail_sendmail(null, [
                    'sendmail' => true,
                    'from' => $from,
                    'mailto' => $to,
                    'dsn_enabled' => false,
                    'charset' => 'UTF-8',
                    'error_handler' => static function (...$args) use ($OUTPUT) {
                        call_user_func_array([$OUTPUT, 'show_message'], $args);
                    },
                ]);

                $MAIL_MIME = $SENDMAIL->create_message($headers, $this->gettext('reportbody'), false, [$attachment]);

                $MAIL_MIME->addAttachment(
                    $attachment['path'],
                    $attachment['mimetype'],
                    $attachment['name'],
                    true,
                    '8bit',
                    'attachment',
                    $attachment['charset'],
                    '',
                    '',
                    $folding ? 'quoted-printable' : null,
                    $folding == 2 ? 'quoted-printable' : null,
                    '',
                    RCUBE_CHARSET
                );

                // keep the SMTP connection open until the last recipient
                $sent = (bool) $SENDMAIL->deliver_message($MAIL_MIME, $i === $last);
                $sent_count += $sent ? 1 : 0;

                if ($message_id !== '') {
                    $this->_log_report_attempt($message_id, $to, $sent);
                }

                if ($debug) {
                    rcube::write_log('markasphishing', $uid . ' -> ' . $to . ' (' . ($sent ? 'sent' : 'failed') . ')');
                }
            }
        }

        if (file_exists($message_file)) {
            unlink($message_file);
        }

        return ['sent' => $sent_count, 'total' => count($recipients)];
    }

    /**
     * The .eml attachment filename is derived from the phishing message's
     * own subject -- attacker-controlled text -- so it's sanitized before
     * use rather than trusted as-is.
     */
    private function _safe_attachment_name($subject)
    {
        $name = preg_replace('/[\x00-\x1f\/\\\\:*?"<>|]/', '_', (string) $subject);
        $name = trim(preg_replace('/\s+/', ' ', $name));
        $name = mb_substr($name, 0, 100);

        return ($name !== '' ? $name : 'message') . '.eml';
    }

    private function _ensure_folder($folder)
    {
        $storage = $this->rcube->get_storage();

        if (!$storage->folder_exists($folder)) {
            $storage->create_folder($folder, true);
        }
    }

    private function _get_user_prefs()
    {
        $saved = (array) ($this->rcube->user->get_prefs()['markasphishing'] ?? []);

        return $saved + [
            'action' => $this->rcube->config->get('markasphishing_default_action', 'folder'),
            'folder' => $this->rcube->config->get('markasphishing_default_folder', 'Phishing'),
            'mark_read' => false,
        ];
    }

    private function _is_admin()
    {
        $admins = (array) $this->rcube->config->get('markasphishing_admins');

        return empty($admins) || in_array($_SESSION['username'], $admins, true);
    }

    private function _ensure_schema()
    {
        if ($this->schema_checked) {
            return;
        }

        $db = $this->rcube->get_dbh();
        $version_table = $db->table_name('system');
        $result = $db->query("SELECT value FROM {$version_table} WHERE name = ?", self::VERSION_KEY);
        $row = $db->fetch_assoc($result);

        if (!$row) {
            $sql = file_get_contents($this->home . '/SQL/mysql.initial.sql');
            $sql = preg_replace('/^--.*$/m', '', $sql); // strip full-line comments before splitting

            foreach (array_filter(array_map('trim', explode(';', $sql))) as $statement) {
                if ($statement !== '') {
                    $db->query($statement);
                }
            }

            $db->query("INSERT INTO {$version_table} (name, value) VALUES (?, ?)", self::VERSION_KEY, self::SCHEMA_VERSION);
        } else {
            // sequential migration chain: each step only runs if the
            // install is still at the version it upgrades from, falling
            // through toward the current version, so an install several
            // versions behind still ends up fully migrated in one call
            // rather than only handling exactly-one-version-behind
            $version = $row['value'];

            if ($version === self::SCHEMA_VERSION_DOMAIN_CONSOLIDATION) {
                // existing installs: consolidate the one-row-per-domain
                // seed data (each provider used to get a separate row per
                // domain it owns) into one row per provider with a
                // comma-separated domain list, matching the current seed
                // format. Only touches is_default rows, so anything an
                // admin added manually is left alone.
                $this->_consolidate_default_domains();
                $version = self::SCHEMA_VERSION_DEDUPE_TABLE;
            }

            if ($version === self::SCHEMA_VERSION_DEDUPE_TABLE) {
                $reported_table = $db->table_name(self::REPORTED_TABLE);
                $db->query(
                    "CREATE TABLE IF NOT EXISTS {$reported_table} ("
                    . 'message_id VARCHAR(255) NOT NULL, '
                    . 'reported_at DATETIME NOT NULL, '
                    . 'PRIMARY KEY (message_id)'
                    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
                );
                $version = self::SCHEMA_VERSION_REPORT_LOG;
            }

            if ($version === self::SCHEMA_VERSION_REPORT_LOG) {
                $log_table = $db->table_name(self::LOG_TABLE);
                $db->query(
                    "CREATE TABLE IF NOT EXISTS {$log_table} ("
                    . 'id INT UNSIGNED NOT NULL AUTO_INCREMENT, '
                    . 'message_id VARCHAR(255) NOT NULL, '
                    . 'recipient VARCHAR(255) NOT NULL, '
                    . 'username VARCHAR(255) NOT NULL, '
                    . 'success TINYINT(1) NOT NULL, '
                    . 'sent_at DATETIME NOT NULL, '
                    . 'PRIMARY KEY (id), '
                    . 'KEY markasphishing_report_log_recipient_idx (recipient), '
                    . 'KEY markasphishing_report_log_username_idx (username), '
                    . 'KEY markasphishing_report_log_sent_at_idx (sent_at)'
                    . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
                );
                $version = self::SCHEMA_VERSION;
            }

            if ($version !== $row['value']) {
                $db->query("UPDATE {$version_table} SET value = ? WHERE name = ?", $version, self::VERSION_KEY);
            }
        }

        $this->schema_checked = true;
    }

    private function _consolidate_default_domains()
    {
        $db = $this->rcube->get_dbh();
        $table = $db->table_name(self::TABLE);

        $result = $db->query("SELECT id, name, report_address, domain FROM {$table} WHERE type = 'provider' AND is_default = 1 ORDER BY name, id");
        $groups = [];

        while ($row = $db->fetch_assoc($result)) {
            $key = $row['name'] . '|' . $row['report_address'];
            $groups[$key]['ids'][] = $row['id'];
            $groups[$key]['domains'][] = $row['domain'];
        }

        foreach ($groups as $group) {
            if (count($group['ids']) <= 1) {
                continue;
            }

            $keep_id = array_shift($group['ids']);
            $db->query("UPDATE {$table} SET domain = ? WHERE id = ?", implode(', ', $group['domains']), $keep_id);

            foreach ($group['ids'] as $remove_id) {
                $db->query("DELETE FROM {$table} WHERE id = ?", $remove_id);
            }
        }
    }

    private function _prefs_fields_html()
    {
        $prefs = $this->_get_user_prefs();

        $action_select = new html_select(['name' => '_post_action', 'id' => 'markasphishing-action']);
        $action_select->add($this->gettext('actionfolder'), 'folder');
        $action_select->add($this->gettext('actiondelete'), 'delete');
        $action_select->add($this->gettext('actionleave'), 'leave');

        $folder_input = new html_inputfield([
            'name' => '_folder',
            'id' => 'markasphishing-folder',
            'value' => $prefs['folder'],
            'size' => 30,
            'disabled' => $prefs['action'] !== 'folder' ? 'disabled' : null,
        ]);

        $mark_read = new html_checkbox(['name' => '_mark_read', 'id' => 'markasphishing-mark-read', 'value' => '1']);

        $table = new html_table(['cols' => 2, 'class' => 'propform']);
        $table->add('title', html::label('markasphishing-action', rcube::Q($this->gettext('prefaction'))));
        $table->add(null, $action_select->show($prefs['action']));
        $table->add('title', html::label('markasphishing-folder', rcube::Q($this->gettext('preffolder'))));
        $table->add(null, $folder_input->show());
        $table->add('title', html::label('markasphishing-mark-read', rcube::Q($this->gettext('prefmarkread'))));
        $table->add(null, $mark_read->show(!empty($prefs['mark_read']) ? '1' : ''));

        return html::tag('h3', null, rcube::Q($this->gettext('prefsheading'))) . $table->show();
    }

    /**
     * Admin-only stat cards drawn from markasphishing_reported. Deliberately
     * simple: that table only ever stores message_id + reported_at (no
     * domain/recipient/outcome detail), so counts over time windows are all
     * that can be shown honestly today -- and even those undercount past
     * whatever markasphishing_dedupe_retention_days is, since rows age out.
     * A fuller breakdown (top spoofed domains, delivery success rate, etc.)
     * would need the table to record more per report, which is a real
     * schema change, not just a UI addition -- left for a future pass.
     */
    private function _stats_html()
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $reported_table = $db->table_name(self::REPORTED_TABLE);
        $log_table = $db->table_name(self::LOG_TABLE);

        $result = $db->query(
            "SELECT COUNT(*) AS total, "
            . "SUM(CASE WHEN reported_at >= {$db->now(-7 * 86400)} THEN 1 ELSE 0 END) AS last7, "
            . "SUM(CASE WHEN reported_at >= {$db->now(-30 * 86400)} THEN 1 ELSE 0 END) AS last30 "
            . "FROM {$reported_table}"
        );
        $row = $db->fetch_assoc($result) ?: [];

        $rate_result = $db->query("SELECT COUNT(*) AS total, SUM(success) AS succeeded FROM {$log_table}");
        $rate_row = $db->fetch_assoc($rate_result) ?: [];
        $rate_total = (int) ($rate_row['total'] ?? 0);
        $success_rate = $rate_total > 0 ? round(((int) ($rate_row['succeeded'] ?? 0)) / $rate_total * 100) . '%' : '—';

        $days = max(1, (int) $this->rcube->config->get('markasphishing_dedupe_retention_days', 90));

        $card = function ($value, $label) {
            return html::div(['class' => 'markasphishing-stat-card'], [
                html::div(['class' => 'markasphishing-stat-value'], rcube::Q((string) $value)),
                html::div(['class' => 'markasphishing-stat-label'], rcube::Q($label)),
            ]);
        };

        $cards = $card((int) ($row['total'] ?? 0), $this->gettext('statstotal'))
            . $card((int) ($row['last7'] ?? 0), $this->gettext('statslast7'))
            . $card((int) ($row['last30'] ?? 0), $this->gettext('statslast30'))
            . $card($success_rate, $this->gettext('statssuccessrate'));

        $top_list = function ($column, $heading) use ($db, $log_table) {
            $result = $db->query(
                "SELECT {$column} AS label, COUNT(*) AS c FROM {$log_table} WHERE success = 1 "
                . "GROUP BY {$column} ORDER BY c DESC LIMIT 5"
            );
            $items = '';

            while ($row = $db->fetch_assoc($result)) {
                $items .= html::tag('li', null, rcube::Q($row['label']) . ' (' . (int) $row['c'] . ')');
            }

            if ($items === '') {
                return '';
            }

            return html::tag('h4', null, rcube::Q($heading))
                . html::tag('ul', ['class' => 'markasphishing-stats-top'], $items);
        };

        return html::div(['class' => 'markasphishing-stats'], $cards)
            . html::p(['class' => 'hint'], rcube::Q($this->gettext(['name' => 'statshint', 'vars' => ['days' => $days]])))
            . $top_list('recipient', $this->gettext('statstopheading'))
            . $top_list('username', $this->gettext('statsmailboxheading'));
    }

    /**
     * Renders the report directory table -- everything meant to live
     * inside the single settings form. Each row's delete icon is a plain
     * trigger element (not a form: forms can't nest inside this one);
     * markasphishing.js builds and submits a hidden form for it on click.
     */
    private function _directory_fields_html()
    {
        $this->_ensure_schema();

        $db = $this->rcube->get_dbh();
        $result = $db->query('SELECT * FROM ' . $db->table_name(self::TABLE) . ' ORDER BY type, name');
        $is_admin = $this->_is_admin();

        $table = new html_table(['cols' => $is_admin ? 7 : 5, 'class' => 'records-table']);
        $table->add_header(null, rcube::Q($this->gettext('coltype')));
        $table->add_header(null, rcube::Q($this->gettext('colname')));
        $table->add_header(null, rcube::Q($this->gettext('coldomain')));
        $table->add_header(null, rcube::Q($this->gettext('coladdress')));
        $table->add_header(null, rcube::Q($this->gettext('colenabled')));

        if ($is_admin) {
            $table->add_header(null, '');
            $table->add_header(null, '');
        }

        $hidden_ids = '';

        while ($row = $db->fetch_assoc($result)) {
            $checkbox_attrs = ['name' => '_enabled[]', 'value' => $row['id']];
            if (!$is_admin) {
                $checkbox_attrs['disabled'] = 'disabled';
            }

            $enabled_box = new html_checkbox($checkbox_attrs);
            $type_label = $row['type'] === 'authority' ? $this->gettext('typeauthority') : $this->gettext('typeprovider');

            $table->add(null, rcube::Q($type_label));
            $table->add(null, rcube::Q($row['name']));
            $table->add(null, rcube::Q($row['domain'] ?? '*'));
            $table->add(null, rcube::Q($row['report_address']));
            $table->add(null, $enabled_box->show(!empty($row['enabled']) ? $row['id'] : ''));

            if ($is_admin) {
                $table->add(null, html::a([
                    'href' => './?_task=settings&_action=plugin.markasphishing.directory-add&_id=' . (int) $row['id'],
                    'class' => 'markasphishing-edit-trigger',
                    'title' => $this->gettext('edit'),
                    'aria-label' => $this->gettext('edit') . ': ' . rcube::Q($row['name']),
                ], ''));

                $table->add(null, html::a([
                    'href' => '#',
                    'class' => 'markasphishing-delete-trigger',
                    'data-id' => (int) $row['id'],
                    'data-confirm' => $this->gettext(['name' => 'confirmdeletenamed', 'vars' => ['name' => $row['name']]]),
                    'title' => $this->gettext('delete'),
                    'aria-label' => $this->gettext('delete') . ': ' . rcube::Q($row['name']),
                ], ''));
            }

            $hidden_ids .= '<input type="hidden" name="_ids[]" value="' . (int) $row['id'] . '">';
        }

        // the table is wider than a phone screen; scroll it independently
        // rather than letting it push the whole page (and the sticky Save
        // bar tied to the page's own scroll context) into horizontal scroll
        $table_html = html::div(['class' => 'markasphishing-table-scroll'], $table->show());

        $body = html::tag('h3', null, rcube::Q($this->gettext('directoryheading')))
            . html::p(null, rcube::Q($this->gettext('directoryintro')));

        if (!$is_admin) {
            return $body . $table_html . html::p(['class' => 'hint'], rcube::Q($this->gettext('notadminhint')));
        }

        $body = $this->_stats_html() . $body;

        $add_link = html::a([
            'href' => './?_task=settings&_action=plugin.markasphishing.directory-add',
            'class' => 'button',
        ], rcube::Q($this->gettext('addheading')));

        return $body . $hidden_ids . $table_html . html::p(['class' => 'formbuttons footerleft'], $add_link);
    }
}
