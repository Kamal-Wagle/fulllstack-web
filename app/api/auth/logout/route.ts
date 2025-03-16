import { NextResponse } from "next/server"
import { cookies } from "next/headers"

export async function POST(request: Request) {
  // Delete the token cookie
  cookies().delete("token")

  // Redirect to login page
  return NextResponse.redirect(new URL("/admin/login", request.url))
}

