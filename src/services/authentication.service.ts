import { User } from "../models/user.model"; // Modèle Sequelize
import jwt from "jsonwebtoken"; // Pour générer le JWT
import { notFound } from "../error/NotFoundError";

const JWT_SECRET = process.env.JWT_SECRET || "thisIsTheSecret"; // Clé secrète pour signer le token

export class AuthenticationService {
  async getScopes(user: User): Promise<string[]> {
    switch (user.username) {
      case "admin":
        return ["read:book", "create:book", "update:book", "delete:book", "read:bookCollection", "create:bookCollection", "update:bookCollection", "delete:bookCollection", "read:user", "create:user", "update:user", "delete:user","read:author", "create:author", "update:author", "delete:author"];
      case "gerant":
        return ["read:book", "create:book", "update:book", "read:user", "create:user", "update:user", "update:all", "delete:BookCollection", "read:author", "create:author", "update:author", "delete:author"];
      case "utilisateur":
        return ["read:user", "read:book", "read:bookCollection", "read:author", "create:BookCollection", "update:BookCollection", "delete:BookCollection"];
      default:
        return ["read:user", "read:book", "read:bookCollection", "read:author"];
    }
  }

  public async authenticate(username: string, password: string): Promise<string> {
    const user = await User.findOne({ where: { username } });

    if (!user) {
      throw notFound("User");
    }

    const decodedPassword = atob(user.password);

    if (password === decodedPassword) {
      const scopes = await this.getScopes(user);

      const token = jwt.sign(
        { username: user.username, scopes },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      return token;
    } else {
      const error = new Error("Wrong password");
      (error as any).status = 403;
      throw error;
    }
  }
}

export const authService = new AuthenticationService();
