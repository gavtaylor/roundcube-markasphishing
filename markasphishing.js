/**
 * markasphishing plugin script
 *
 * @licstart  The following is the entire license notice for the
 * JavaScript code in this file.
 *
 * Copyright (C) Gavin Taylor
 *
 * The JavaScript code in this page is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * @licend  The above is the entire license notice
 * for the JavaScript code in this file.
 */

rcube_webmail.prototype.markasphishing_report = function () {
    var uids = this.env.uid ? [this.env.uid] : this.message_list.get_selection();
    if (!uids || !uids.length) {
        return;
    }

    if (!confirm(this.get_label('markasphishing.confirmreport'))) {
        return;
    }

    var lock = this.set_busy(true, 'loading');
    this.http_post('plugin.markasphishing.report', this.selection_post_data({ _uid: uids }), lock);
};

// server tells us what happened to the reported message(s): moved to a
// folder, deleted, or left in place (mbox/do_delete both falsy)
rcube_webmail.prototype.markasphishing_move = function (mbox, do_delete, uids) {
    var prev_uid = this.env.uid;

    if (this.message_list && uids.length == 1 && !this.message_list.in_selection(uids[0])) {
        this.env.uid = uids[0];
    }

    if (do_delete) {
        this.delete_messages();
    } else if (mbox) {
        this.move_messages(mbox);
    } else {
        this.command('list');
    }

    this.env.uid = prev_uid;
};

if (window.rcmail) {
    rcmail.addEventListener('init', function () {
        rcmail.register_command('plugin.markasphishing.report', function () {
            rcmail.markasphishing_report();
        }, rcmail.env.uid);

        if (rcmail.message_list) {
            rcmail.message_list.addEventListener('select', function (list) {
                rcmail.enable_command('plugin.markasphishing.report', list.get_selection(false).length > 0);
            });
        }
    });

    // Settings > Phishing Reporting: keep the folder-name field's disabled
    // state in sync with the post-report action select.
    //
    // This turned out not to reliably go through any single DOM event at
    // all for this particular native <select>: bubble-phase 'change',
    // capture-phase 'change'/'input', and even 'click'/'mouseup' on the
    // select were each observed to sometimes fire and sometimes not for
    // the exact same user action (switching to "A dedicated folder"),
    // both in testing and in real use. Rather than keep guessing at event
    // types, this just polls the select's value directly -- correctness
    // no longer depends on any event firing at all, only a bounded delay
    // (<=400ms) before the field's state catches up.
    var markasphishingSyncFolderDisabled = function () {
        var sel = document.getElementById('markasphishing-action');
        var folder = document.getElementById('markasphishing-folder');
        if (sel && folder) {
            folder.disabled = sel.value !== 'folder';
        }
    };
    setInterval(markasphishingSyncFolderDisabled, 400);

    // Settings > Phishing Reporting: each report-directory row's delete
    // icon isn't inside its own <form> (it can't be -- it's nested inside
    // the page's single main form, and forms don't nest), so build and
    // submit a one-off form for it here instead.
    document.addEventListener('click', function (e) {
        var trigger = e.target.closest && e.target.closest('.markasphishing-delete-trigger');
        if (!trigger) {
            return;
        }

        e.preventDefault();

        if (!confirm(trigger.getAttribute('data-confirm') || 'Delete this entry?')) {
            return;
        }

        var form = document.createElement('form');
        form.method = 'post';
        form.action = './?_task=settings&_action=plugin.markasphishing.directory-delete';

        var idField = document.createElement('input');
        idField.type = 'hidden';
        idField.name = '_id';
        idField.value = trigger.getAttribute('data-id');
        form.appendChild(idField);

        // Roundcube auto-injects this into every server-rendered POST
        // form, but a form built client-side after the page already
        // loaded never gets that treatment -- without it, the request
        // is rejected as a CSRF check failure
        var tokenField = document.createElement('input');
        tokenField.type = 'hidden';
        tokenField.name = '_token';
        tokenField.value = rcmail.env.request_token;
        form.appendChild(tokenField);

        document.body.appendChild(form);
        form.submit();
    }, true);
}
