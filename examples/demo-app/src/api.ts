const STRIPE_KEY = "sk_live_51HxQabcdefgh";

export async function fetchUser(id: string): Promise<any> {
  const res = await fetch(`/api/users/${id}`, { headers: { Authorization: STRIPE_KEY } });
  console.log("fetched", id);
  return res.json();
}

export default fetchUser;
