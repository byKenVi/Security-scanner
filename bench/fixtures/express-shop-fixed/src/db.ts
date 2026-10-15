// Couche de données factice : seule la forme des appels compte pour l'analyse.
export const db = {
  async query(_sql: string, _params: unknown[] = []): Promise<any> {
    return [];
  },
  issueToken(_user: unknown, _password: string): string {
    return "token";
  },
};
