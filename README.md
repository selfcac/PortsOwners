# PortsOwners

A tool to query the IP tables and find which process opened each TCP/UDP connection. Also what user opened this process. We use this tool to determine wether to filter a connection if it was opened by non admin user.

## How to use

You can print the User\Groups hierarchy of the computer:
```PrincipalUtils.PrintInfo((c) => Console.WriteLine(c));```

You can get a specific TCP table reading (v4\v6) - connection list:
```
foreach (var row in PortUtitlities.GetIP4(logError).OrderBy((s)=>s.LocalAddress.ToString()))
    {
        string UserName = row.OwnerPid > 4 ? ProcessUtilities.sidFromProcess(row.OwnerPid) : "System";
        Console.WriteLine("v4 {0}:{1}->{2}:{3} @ {4} Mode: {5}",
            row.LocalAddress, row.LocalPort, row.RemoteAddress, row.RemotePort, UserName, row.State);
    }
```
You can use the built in `NetworkWatcher` to automatically refresh the tables and only query if a source address is non admin with one call:

```
NetworkWatcher nw = new NetworkWatcher();
nw.Start(5);

string input = "";
do
{
    input = Console.ReadLine();
    Console.WriteLine("Is Admin? " + nw.isLocalAddressAdmin(input, true /* Assume Access denied */));
} while (input != "q");

nw.Stop();
```


## Credits

* [CitadelCore](https://github.com/TechnikEmpire/CitadelCore)
* https://social.msdn.microsoft.com/Forums/en-US/f3c56180-8e8a-4ecf-9709-94e2c30ff706/how-to-check-if-users-sid-is-in-local-administrator-group?forum=vbgeneral
* https://www.codeproject.com/Articles/14828/How-To-Get-Process-Owner-ID-and-Current-User-SID