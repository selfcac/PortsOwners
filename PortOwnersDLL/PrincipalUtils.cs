using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Principal;
using System.DirectoryServices.AccountManagement;

namespace PortsOwners
{
    public class PrincipalUtils
    {
        public static string BuiltinAdminGroup = 
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).ToString(); // "S-1-5-32-544";
            

        public static void PrintInfo(Action<string> log)
        {
            var machineContext = new PrincipalContext(ContextType.Machine);
            var userPrincipal = new UserPrincipal(machineContext);
            var userPrincipalSearcher = new PrincipalSearcher(userPrincipal);

            foreach(var user in userPrincipalSearcher.FindAll())
            {
                log(string.Format("[User] Name: {0}\tSID:{1}", user.Name, user.Sid.ToString()));
                foreach (var group in user.GetGroups())
                {
                    log(string.Format("\t[Group] Name: {0}\tSID:{1}", group.Name, group.Sid.ToString()));
                }
            }
        }

        public static void getLimitedUsers(Action<string,string> callbackNameAndSid)
        {
            var machineContext = new PrincipalContext(ContextType.Machine);
            var userPrincipal = new UserPrincipal(machineContext);
            var userPrincipalSearcher = new PrincipalSearcher(userPrincipal);

            foreach (var user in userPrincipalSearcher.FindAll())
            {
                //log(string.Format("[User] Name: {0}\tSID:{1}", user.Name, user.Sid.ToString()));

                bool isAdmin = false;
                foreach (var group in user.GetGroups())
                {
                    //log(string.Format("\t[Group] Name: {0}\tSID:{1}", group.Name, group.Sid.ToString()));
                    if (group.Sid.ToString() == BuiltinAdminGroup)
                    {
                        isAdmin = true;
                        break;
                    }
                }

                if (!isAdmin)
                {
                    callbackNameAndSid(user.Name, user.Sid.ToString());
                }
            }
        }


    }
}
