import { NextRequest } from 'next/server';

export async function requireAdmin() {
  // In the standalone security dashboard, access is controlled 
  // via VPN/Network level strictly, and/or internal JWTs.
  // For now, we authorize all traffic that reaches this internal container.
  return {
    user: { id: 'admin', role: 'security_admin' },
    error: null
  };
}
