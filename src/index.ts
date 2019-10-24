import { promises as dnsPromises } from 'dns';
import Axios, { AxiosResponse, AxiosRequestConfig } from 'axios';
import * as ipRangeCheck from 'ip-range-check';

const { lookup } = dnsPromises;

// https://github.com/jtdowney/private_address_check/blob/0498dcf8e0705c45b1f888e24be59939e5aecbcb/lib/private_address_check.rb#L11
const CIDRList = [
  '127.0.0.0/8', // Loopback
  '::1/128', // Loopback
  '0.0.0.0/8', // Current network (only valid as source address)
  '169.254.0.0/16', // Link-local
  '10.0.0.0/8', // Private network
  '100.64.0.0/10', // Shared Address Space
  '172.16.0.0/12', // Private network
  '192.0.0.0/24', // IETF Protocol Assignments
  '192.0.2.0/24', // TEST-NET-1, documentation and examples
  '192.88.99.0/24', // IPv6 to IPv4 relay (includes 2002::/16)
  '192.168.0.0/16', // Private network
  '198.18.0.0/15', // Network benchmark tests
  '198.51.100.0/24', // TEST-NET-2, documentation and examples
  '203.0.113.0/24', // TEST-NET-3, documentation and examples
  '224.0.0.0/4', // IP multicast (former Class D network)
  '240.0.0.0/4', // Reserved (former Class E network)
  '255.255.255.255', // Broadcast
  '64:ff9b::/96', // IPv4/IPv6 translation (RFC 6052)
  '100::/64', // Discard prefix (RFC 6666)
  '2001::/32', // Teredo tunneling
  '2001:10::/28', // Deprecated (previously ORCHID)
  '2001:20::/28', // ORCHIDv2
  '2001:db8::/32', // Addresses used in documentation and example source code
  '2002::/16', // 6to4
  'fc00::/7', // Unique local address
  'fe80::/10', // Link-local address
  'ff00::/8', // Multicast
];

export function isPrivateAddress(ip: string): boolean {
  const range = CIDRList.find(r => {
    return ipRangeCheck(ip, r);
  });

  if (range) {
    return true;
  }

  return false;
}

async function getIpAddress(hostname: string): Promise<string> {
  return (await lookup(hostname)).address;
}

const safeAxios = {
  async request<T = any, R = AxiosResponse<T>>(
    config: AxiosRequestConfig,
  ): Promise<R> {
    const { url, baseURL, headers, params } = config;

    const { hostname, protocol, pathname, searchParams } = new URL(
      url || '',
      baseURL,
    );

    console.log(protocol);

    if (protocol !== 'http:' && protocol !== 'https:') {
      throw new Error('url is invalid');
    }

    if (!hostname) {
      throw new Error('hostname is invalid');
    }

    const ip = await getIpAddress(hostname);

    if (isPrivateAddress(ip) || isPrivateAddress(hostname)) {
      throw new Error('hostname is not valid');
    }

    return await Axios.request<T, R>({
      ...config,
      url: pathname,
      params: {
        ...searchParams,
        ...params,
      },
      baseURL: `${protocol}//${ip}`,
      headers: {
        ...headers,
        Host: hostname,
      },
    });
  },
};

export default safeAxios;
