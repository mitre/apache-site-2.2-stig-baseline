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

control "V-15334" do
  title "Web sites must utilize ports, protocols, and services according to
PPSM guidelines."
  desc  "Failure to comply with DoD ports, protocols, and services (PPS)
requirements can result
    in compromise of enclave boundary protections and/or functionality of the
AIS.

    The IAM will ensure web servers are configured to use only authorized PPS
in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1,
Ports, Protocols, and Services Management (PPSM), and the associated Ports,
Protocols, and Services (PPS) Assurance Category Assignments List.

  "
  impact 0.3
  tag "gtitle": "WG610"
  tag "gid": "V-15334"
  tag "rid": "SV-34015r1_rule"
  tag "stig_id": "WG610 A22"
  tag "fix_id": "F-26863r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Information Assurance Officer"
  tag "ia_controls": "DCPP-1"
  tag "check": "Review the web site to determine if HTTP and HTTPs are used in
accordance with well known ports (e.g., 80 and 443) or those ports and services
as registered and approved for use by the DoD PPSM. Any variation in PPS will
be documented, registered, and approved by the PPSM. If not, this is a finding."
  tag "fix": "Ensure the web site enforces the use of IANA well-known ports for
HTTP and HTTPS."

  if virtualization.system == 'docker'
      describe "Since this apache instance is running in a container, perform manual review to determine if HTTP and HTTPS are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use." do
      skip "Since this apache instance is running in a container, perform manual review to determine if HTTP and HTTPS are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use." 
      end
  
  else
  
    describe port(80) do
      it { should be_listening }
      its('processes') { should include 'httpd' }
    end

    describe port(443) do
      it { should be_listening }
      its('processes') { should include 'httpd' }
    end
  
  end

end
