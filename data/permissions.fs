# Use this file to set root directory and access permissions per role.  
# Assign users to a role in user_roles.fs
#
# Examples:
#   admin=/,rw (Read/Write access to the entire filevault for admin role)
#   readonly=/,r (Read only access to the entire filevault for readonly role)
#   invoice=/documents/financials/invoices/,r (Read only access to the /documents/financials/invoices/ directory for invoice role)
# 
role=root_directory,r[w]
