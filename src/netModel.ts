/**
 * netModel.ts — THE single authoritative network identity model.
 *
 * Two fundamentally different IP roles live in this project and they must
 * never be conflated:
 *
 *   1. AWS_EC2_ELASTIC_IP — the EC2 destination we SSH to AND the egress IP
 *      the proxy chain is expected to present to the internet. It is a
 *      STATIC Elastic IP: it never changes when the laptop roams.
 *   2. The laptop's current public IP — dynamic, changes across university /
 *      home / cafe / hotspot networks. It is only ever OBSERVED (directly,
 *      proxy-bypassed) and used as the SOURCE /32 in AWS SG authorization.
 *      It has NO default value and is never hardcoded anywhere.
 *
 * Rules enforced by this module:
 * - awsElasticIp === awsSshHost === expectedProxyEgressIp (one constant, one
 *   source of truth). Nothing else in src/ may hardcode a literal IP.
 * - AWS_REGION is the home of the Elastic IP.
 * - The laptop public IP is NEVER compared against the Elastic IP as though
 *   they were the same kind of thing; a mismatch between them is NORMAL.
 *
 * Changing the EC2 instance means changing ONE constant here (plus optionally
 * the opencodeProxyHealth.ec2Host / expectedExternalIp settings, which default
 * from this module).
 */

/** The AWS EC2 Elastic IP (STATIC — never changes with the laptop's network). */
export const AWS_ELASTIC_IP = '16.192.228.28';

/** SSH destination = the Elastic IP (same machine, same identity). */
export const AWS_SSH_HOST = AWS_ELASTIC_IP;

/** Expected egress IP seen through SOCKS/HTTP proxy = the Elastic IP. */
export const EXPECTED_PROXY_EGRESS_IP = AWS_ELASTIC_IP;

/** AWS region that hosts the Elastic IP. */
export const AWS_REGION = 'eu-north-1';

/** Local loopback endpoints (unchanged by any of the above). */
export const LOCAL_SOCKS_HOST = '127.0.0.1';
export const LOCAL_HTTP_HOST = '127.0.0.1';

/**
 * True when two IPs are "the same AWS identity". Deliberately the ONLY place
 * an equality check between an observed egress IP and the Elastic IP exists
 * at the model level; callers must use this instead of ad-hoc comparisons so
 * the invariant stays greppable.
 */
export function isExpectedEgressIp(observed: string): boolean {
  return observed.trim() === AWS_ELASTIC_IP;
}

/**
 * The laptop public IP is dynamic — this function documents (for audits) that
 * any value is plausible and that it must never be compared with the Elastic
 * IP as an error condition. It exists so callers can express intent:
 *   if (laptopIp === AWS_ELASTIC_IP) -> legal but meaningless coincidence.
 */
export function isLaptopPublicIp(_ip: string): boolean {
  return true;
}
