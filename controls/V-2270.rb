APACHE_HOME= attribute(
  'apache_home',
  description: 'location of apache home directory',
  default: '/etc/httpd'
)

APACHE_CONF_DIR= attribute(
  'apache_conf_dir',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)

APACHE_LOG_DIR= attribute(
  'apache_log_dir',
  description: 'location of apache log directory',
  default: '/etc/httpd/logs'
)

control "V-2270" do
  title "Anonymous FTP user access to interactive scripts is prohibited."
  desc  "The directories containing the CGI scripts, such as PERL, must not be
accessible to anonymous users via FTP. This applies to all directories that
contain scripts that can dynamically produce web pages in an interactive manner
(i.e., scripts based upon user-provided input). Such scripts contain
information that could be used to compromise a web service, access system
resources, or deface a web site."
  impact 0.5
  tag "gtitle": "WG430"
  tag "gid": "V-2270"
  tag "rid": "SV-36641r1_rule"
  tag "stig_id": "WG430 A22"
  tag "fix_id": "F-26838r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "ia_controls": "ECCD-1, ECCD-2"
  tag "check": "Locate the directories containing the CGI scripts. These
directories should be language-specific (e.g., PERL, ASP, JS, JSP, etc.).

Using ls –al, examine the file permissions on the CGI, the cgi-bin, and the
cgi-shl directories.

Anonymous FTP users must not have access to these directories.

If the CGI, the cgi-bin, or the cgi-shl directories can be accessed by any
group that does not require access, this is a finding.
"
  tag "fix": "If the CGI, the cgi-bin, or the cgi-shl directories can be
accessed via FTP by any group or user that does not require access, remove
permissions to such directories for all but the web administrators and the SAs.
Ensure that any such access employs an encrypted connection. "

  describe directory("/var/www/cgi-bin/") do
    its('owner') { should cmp 'apache' }
    its('group') { should cmp 'apache' }
  end

  if directory("/var/www/cgi-shl").exist?
    its('owner') { should cmp 'apache' }
    its('group') { should cmp 'apache' }
  end

  if directory("/var/www/cgi").exist?
    its('owner') { should cmp 'apache' }
    its('group') { should cmp 'apache' }
  end
end
