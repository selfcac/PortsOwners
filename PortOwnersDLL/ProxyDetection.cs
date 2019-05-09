using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace PortOwnersDLL
{
    public class ProxyDetection
    {
        public static bool ContainsPrivateIpv4Address(byte[] bytes)
        {
            if (bytes.Length < 4)
            {
                return false;
            }

            switch (bytes[0])
            {
                case 127:
                case 10:
                    {
                        return true;
                    }

                case 192:
                    {
                        return bytes[1] == 168;
                    }

                case 172:
                    {
                        return (bytes[1] >= 16 && bytes[1] <= 31);
                    }

                default:
                    return false;
            }
        }

        public static bool ContainsPrivateIpv4Address(string address)
        {
            IPAddress ip = IPAddress.Any;
            if (IPAddress.TryParse(address, out ip))
            {
                return ContainsPrivateIpv4Address(ip.GetAddressBytes());
            }
            else
            {
                return false;
            }
        }

        public static bool IsSocksProxyConnect(byte[] payload)
        {
            if (payload.Length < 8)
            {
                return false;
            }

            var socksVersion = payload[0];

            switch (socksVersion)
            {
                case 4:
                    {
                        // Socks4 RFC: http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol

                        // External destination port number.
                        ushort port = (ushort)((payload[2] << 8) | payload[3]);

                        if (port == 80 || port == 443)
                        {
                            // External destination IP address.
                            byte[] extIp = new[] { payload[4], payload[5], payload[6], payload[7] };

                            if (!ContainsPrivateIpv4Address(extIp))
                            {
                                // SOCKS4 connect detected.
                                return true;
                            }
                        }
                    }
                    break;

                case 5:
                    {
                        // Socks5 RFC: https://www.ietf.org/rfc/rfc1928.txt

                        // o CONNECT X'01' o BIND X'02' o UDP ASSOCIATE X'03'
                        var command = payload[1];

                        if (command == 1)
                        {
                            // o IP V4 address: X'01' o DOMAINNAME: X'03' o IP V6 address: X'04'
                            var addressType = payload[3];

                            switch (addressType)
                            {
                                case 1:
                                    {
                                        if (payload.Length < 10)
                                        {
                                            // Payload can't possibly be holding IPV4 address + port number.
                                            return false;
                                        }

                                        ushort port = (ushort)((payload[8] << 8) | payload[9]);

                                        if (port == 80 || port == 443)
                                        {

                                            // External destination IP address.
                                            byte[] extIp = new[] { payload[4], payload[5], payload[6], payload[7] };

                                            if (!ContainsPrivateIpv4Address(extIp))
                                            {
                                                // SOCKS5 connect detected.
                                                return true;
                                            }
                                        }
                                    }
                                    break;

                                case 3:
                                    {
                                        // The address field contains a fully-qualified domain name.
                                        // The first octet of the address field contains the number
                                        // of octets of name that follow, there is no terminating NUL octet.

                                        var domainLength = payload[4];

                                        if (payload.Length < (domainLength + 6))
                                        {
                                            // Domain length + 16 bit port number extends beyond the
                                            // packet payload length.
                                            return false;
                                        }

                                        // We don't need the domain name, but here it is anyway.
                                        // std::string domainName(payload + 5, domainLength);

                                        ushort port = (ushort)((payload[5 + domainLength] << 8) | payload[6 + domainLength]);

                                        if (port == 80 || port == 443)
                                        {
                                            // SOCKS5 domain connect to domain name detected.
                                            return true;
                                        }
                                    }
                                    break;

                                case 4:
                                    {
                                        if (payload.Length < 22)
                                        {
                                            // Payload can't possibly be holding IPV6 address + port number.
                                            return false;
                                        }

                                        ushort port = (ushort)((payload[20] << 8) | payload[21]);

                                        if (port == 80 || port == 443)
                                        {
                                            // SOCKS5 IPV6 connect detected. Blocking.
                                            return true;
                                        }
                                    }
                                    break;

                                default:
                                    return false;
                            }
                        }
                    }
                    break;

                default:
                    return false;
            }

            return false;
        }

        static byte[] HTTPsConnect = Encoding.ASCII.GetBytes("CONNECT ");

        public static bool IsHttpsConnect(byte[] payload)
        {
            bool headerEqual = true;

            for (int i = 0; i < HTTPsConnect.Length; i++)
            {
                if (HTTPsConnect[i] != payload[i])
                {
                    headerEqual = false;
                    break;
                }
            }

            return headerEqual;
        }

    }
}
