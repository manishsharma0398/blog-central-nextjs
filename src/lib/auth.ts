import { NextAuthOptions, User } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcrypt";
import { db } from "./db";

const nextAuthOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      type: "credentials",
      credentials: {
        email: {
          label: "Email",
          placeholder: "abc@xyz.com",
          type: "email",
        },
        password: {
          label: "Password",
          placeholder: "Your password",
          type: "password",
        },
      },
      async authorize(credentials, req) {
        if (!credentials || !credentials?.email || !credentials.password)
          return null;

        if (credentials.email && credentials.password) {
          const user = await db.user.findFirst({
            where: {
              email: credentials.email,
            },
          });

          if (!user) {
            const encryptedPassword = bcrypt.hashSync(credentials.password, 10);

            const newUser = await db.user.create({
              data: {
                email: credentials.email,
                password: encryptedPassword,
                role: "USER",
              },
            });
          } else {
            const passwordMatched = bcrypt.compareSync(
              credentials.password,
              user.password
            );

            if (!passwordMatched) return null;

            const { password, ...data } = user;
            console.log({ data });

            return data as User;
          }
        }

        return null;
      },
    }),
  ],
};

export default nextAuthOptions;
