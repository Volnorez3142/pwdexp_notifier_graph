**As any other Powershell file, you might need to unlock this one before opening through RMB > Properties > Unlock.**

Since we live in a world, where On-Premises AD has no out-of-box utility to adequately notify the user of his soon to expire password, there is a natural need to come up with something that will do that.
This time, I humbly present you this simple (and yet effective) PS script that utilizes Microsoft Graph API and sends an email to users who's password is about to expire.

It can be run manually or headless through the Task Scheduler.
However, this time you will need to manually set up the connection to your Tenant and App that has the Graph API Mail.Send consent, aswell as the scope from which the users will be parsed (in form of a simple DistinguishedName attribute).

The code is fairly simple and relatively small, the design can be considered borderline intuitive. Since you, as an infrastructure engineer, will need to set it up for your needs, I will keep the readme minimal and simply wish you good luck setting and modifying this up to your needs. 

As a nice-to-have, it logs separately every run into a C:\by3142\PasswordNotifier folder.
