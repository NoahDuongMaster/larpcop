export interface User {
  id: string;
  name: string;
}

export function displayName(user: User): string {
  return user.name.trim();
}
