import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import * as bcrypt from 'bcryptjs';
import { neon } from '@neondatabase/serverless';

type AuthUser = {
  id: string;
  name: string;
  email: string;
  password?: string;
};
 
const sql = neon(process.env.POSTGRES_URL!);

async function getUser(email: string): Promise<AuthUser | undefined> {
    try {
      const users = await sql`SELECT * FROM users WHERE email=${email}`;
      if (!users || users.length === 0) return undefined;
      
      const user = users[0];
      return {
        id: String(user.id),
        name: String(user.name),
        email: String(user.email),
        password: String(user.password)
      };
    } catch (error) {
      console.error('Failed to fetch user:', error);
      throw new Error('Failed to fetch user.');
    }
  }
 
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
        async authorize(credentials) {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);

            if (!parsedCredentials.success) {
                throw new Error('Invalid credentials');
            }

            if (parsedCredentials.success) {

            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);
            if (!user) return null;
            const passwordsMatch = bcrypt.compareSync(password, user.password!);
    
            if (passwordsMatch) return user;
            }

            return null;
        },
      }),
  ],
});