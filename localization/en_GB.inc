<?php

/*
 +-----------------------------------------------------------------------+
 | Localization file of the markasphishing Roundcube plugin              |
 |                                                                       |
 | Copyright (C) Gavin Taylor                                            |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version. See the README file for a full license statement. |
 +-----------------------------------------------------------------------+
*/

$labels = [];
$labels['report'] = 'Phishing';
$labels['buttonreport'] = 'This message is a phishing attempt';
$labels['confirmreport'] = 'Report this message as phishing? It will be forwarded to the configured providers and authorities.';

$labels['settingstitle'] = 'Phishing Reporting';
$labels['prefsheading'] = 'My reporting preferences';
$labels['prefaction'] = 'After reporting, move the message to';
$labels['preffolder'] = 'Folder name';
$labels['prefmarkread'] = 'Mark as read after reporting';
$labels['actionfolder'] = 'A dedicated folder';
$labels['actiondelete'] = 'Trash';
$labels['actionleave'] = 'Leave it where it is';
$labels['save'] = 'Save';
$labels['delete'] = 'Delete';
$labels['edit'] = 'Edit';

$labels['statstotal'] = 'Reports tracked';
$labels['statslast7'] = 'Last 7 days';
$labels['statslast30'] = 'Last 30 days';
$labels['statssuccessrate'] = 'Delivery success rate';
$labels['statshint'] = 'Only reflects reports from the last $days days -- older entries are cleaned up automatically.';
$labels['statstopheading'] = 'Top reported addresses';
$labels['statsmailboxheading'] = 'Most-targeted mailboxes';

$labels['directoryheading'] = 'Report directory';
$labels['directoryintro'] = 'Providers are matched against the sender\'s domain; authorities are always included for every report.';
$labels['coltype'] = 'Type';
$labels['colname'] = 'Name';
$labels['coldomain'] = 'Domain(s)';
$labels['coladdress'] = 'Report address';
$labels['coldescription'] = 'Description';
$labels['colenabled'] = 'Enabled';
$labels['typeprovider'] = 'Provider';
$labels['typeauthority'] = 'Authority';
$labels['domainhint'] = 'Single or multiple comma-separated hostnames, e.g. gmail.com, googlemail.com (providers only)';
$labels['addheading'] = 'Add a new entry';
$labels['editheading'] = 'Edit entry';
$labels['cancel'] = 'Cancel';
$labels['notadminhint'] = 'You do not have permission to edit the report directory on this server. Ask an administrator listed in markasphishing_admins.';

$messages = [];
$messages['reportedasphishing'] = 'Reported as phishing';
$messages['reportfailed'] = 'Could not report this message: no address could be found or reached';
$messages['reportpartial'] = 'Reported as phishing, but $failed of $total report emails could not be delivered';
$messages['reportskipped'] = 'Already reported previously; not reported again';
$messages['reportsubject'] = 'Phishing report: $subject';
$messages['reportbody'] = 'A message suspected of being a phishing attempt is attached for your review.';
$messages['prefssaved'] = 'Preferences saved';
$messages['directorysaved'] = 'Report directory updated';
$messages['directorydeleted'] = 'Entry deleted';
$messages['directorydomainrequired'] = 'A domain is required for provider entries';
$messages['notadmin'] = 'You do not have permission to edit the report directory';
$messages['confirmdeletenamed'] = 'Delete "$name" from the report directory?';
