import { Injectable } from '@nestjs/common';
import { randomBytes, scryptSync } from 'crypto';

type UserId = string;
type SessionId = string;

export interface UserCredential {
  email: string;
  password: string;
  salt?: string;
}

export interface UserSession {
  id: SessionId;
  userId: string;
  validUntil: Date;
}

const USER_DB = new Map<UserId, UserCredential>();
const USER_SESSION = new Map<SessionId, UserSession>();

@Injectable()
export class AuthService {
  tryLogin(email: string, password: string): UserSession {
    if (USER_DB.has(email)) {
      // Check if password match
      //
      const userData = USER_DB.get(email);

      const salt = userData.salt;
      const hashedPassword = scryptSync(password, salt, 64);
      const passwordCandidate = hashedPassword.toString('hex');

      if (passwordCandidate !== userData.password) {
        throw new Error('Mismatched email & password combination');
      }

      const sessionBuf = randomBytes(32);
      const sessionId = sessionBuf.toString('hex');

      const newSession = {
        id: `${new Date().getTime()}--${sessionId}`,
        userId: email,
        validUntil: new Date(), // No actual session expiry is checked
      };

      return newSession;
    }

    throw new Error('No user found');
  }

  registerUser(credentials: UserCredential): UserSession {
    // Save to DB for future use
    const { email, password } = credentials;
    const userId: UserId = `${credentials.email}`;

    if (USER_DB.has(userId)) {
      throw new Error('User has already registered');
    }

    const buf = randomBytes(256);
    const salt = buf.toString('hex');
    const hashedPassword = scryptSync(password, salt, 64);

    USER_DB.set(userId, {
      email,
      password: hashedPassword.toString('hex'),
      salt,
    });

    const sessionBuf = randomBytes(32);
    const sessionId = sessionBuf.toString('hex');

    const newSession = {
      id: `${new Date().getTime()}--${sessionId}`,
      userId: userId,
      validUntil: new Date(), // No actual session expiry is checked
    };

    USER_SESSION.set(newSession.id, newSession);

    return newSession;
  }
}
