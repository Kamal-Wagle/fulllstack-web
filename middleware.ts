import { type NextRequest, NextResponse } from "next/server"

export async function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname
  console.log("Request path:", path) // Debug: Log the current request path

  // Define paths that should be excluded from authentication
  const isPublicPath =
    path === "/admin/login" ||
    path.startsWith("/api/auth/") ||
    path.startsWith("/api/seed") ||
    path.includes("/_next/") ||
    path.includes("/favicon.ico")
  console.log("Is public path:", isPublicPath) // Debug: Log whether the path is public

  // Only protect admin routes that aren't public
  if (path.startsWith("/admin") && !isPublicPath) {
    console.log("Admin path detected, checking authentication...") // Debug: Log the check for admin path

    const token = request.cookies.get("token")?.value
    console.log("Token from cookies:", token) // Debug: Log the token retrieved from cookies

    if (!token) {
      console.log("No token found, redirecting to /admin/login") // Debug: Log when no token is found
      const url = new URL("/admin/login", request.url)
      return NextResponse.redirect(url)
    }

    console.log("Token found, continuing with the request") // Debug: Log when a token is found
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/admin/:path*"],
}
