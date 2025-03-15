import { cookies } from "next/headers"
import { SignJWT, jwtVerify } from "jose"
import { redirect } from "next/navigation"
import bcrypt from "bcryptjs"
import { v4 as uuidv4 } from "uuid"
import { ensureServerOnly } from "./server-only"

// Ensure this code only runs on the server
ensureServerOnly()

import User from "@/lib/models/user"
import { connectToDatabase } from "@/lib/db"

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET
console.log(JWT_SECRET , "from top of auth.ts")

if (!JWT_SECRET) {
    console.log("jwt secret key is not found // this is from auth.js page")
  throw new Error("JWT_SECRET environment variable is not defined")
}

// Create a JWT token
export async function createToken(payload: any) {
  console.log("Creating token with payload:", payload) // Debug: Log payload
  const jti = uuidv4()
  console.log("Generated jti:", jti) // Debug: Log the generated jti

  const token = await new SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(new TextEncoder().encode(JWT_SECRET))

  console.log("Created token:", token) // Debug: Log the created token
  return token
}

// Verify a JWT token
export async function verifyToken(token: string) {
  console.log("Verifying token:", token) // Debug: Log the token being verified
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(JWT_SECRET), {
      clockTolerance: 15, // 15 seconds of clock skew allowed
    })
    console.log("Token verified successfully, payload:", payload) // Debug: Log the verified payload
    return payload
  } catch (error) {
    console.error("Token verification error:", error)
    return null
  }
}

// Set a JWT token in cookies
export async function setTokenCookie(token: string) {
  console.log("Setting token in cookies:", token) // Debug: Log the token to be set in cookies
  cookies().set({
    name: "token",
    value: token,
    httpOnly: true,
    path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 8, // 8 hours
    sameSite: "strict",
  })
  console.log("Token cookie set successfully") // Debug: Log that the token cookie was set
}

// Get the current user from the token
export async function getCurrentUser() {
  console.log("Getting current user") // Debug: Log the start of user retrieval
  try {
    const token = cookies().get("token")?.value
    console.log("Token retrieved from cookies:", token) // Debug: Log the token

    if (!token) {
      return null
    }

    const payload = await verifyToken(token)
    if (!payload || !payload.id) {
      console.log("Invalid token payload:", payload) // Debug: Log invalid payload
      return null
    }

    await connectToDatabase()
    const user = await User.findById(payload.id).select("-password")
    console.log("User found:", user) // Debug: Log the found user

    if (!user) {
      return null
    }

    return {
      id: user._id.toString(),
      username: user.username,
      role: user.role,
    }
  } catch (error) {
    console.error("Error getting current user:", error)
    return null
  }
}

// Get user from request (for middleware)
export async function getUser() {
  console.log("Getting user") // Debug: Log the start of user retrieval
  try {
    const token = cookies().get("token")?.value
    console.log("Token retrieved from cookies:", token) // Debug: Log the token

    if (!token) {
      return null
    }

    const payload = await verifyToken(token)
    if (!payload || !payload.id) {
      console.log("Invalid token payload:", payload) // Debug: Log invalid payload
      return null
    }

    return {
      id: payload.id,
      username: payload.username,
      role: payload.role,
    }
  } catch (error) {
    console.error("Error getting user:", error)
    return null
  }
}

// Check if the user is authenticated
export async function requireAuth(requiredRole?: "admin" | "staff") {
  console.log("Checking authentication") // Debug: Log authentication check
  const user = await getCurrentUser()

  if (!user) {
    console.log("User not authenticated") // Debug: Log when user is not authenticated
    redirect("/admin/login")
  }

  // If a specific role is required, check if the user has that role
  if (requiredRole && user.role !== requiredRole) {
    console.log("User role mismatch, redirecting") // Debug: Log role mismatch
    // If admin role is required but user is staff, redirect to dashboard
    if (requiredRole === "admin" && user.role === "staff") {
      redirect("/admin")
    }
  }

  return user
}

// Hash a password
export async function hashPassword(password: string) {
  console.log("Hashing password") // Debug: Log password hashing process
  // Use a higher cost factor for better security
  return bcrypt.hash(password, 12)
}

// Compare a password with a hash
export async function comparePassword(password: string, hash: string) {
  console.log("Comparing password with hash") // Debug: Log password comparison
  // Use a constant-time comparison to prevent timing attacks
  return bcrypt.compare(password, hash)
}

// Logout the user
export async function logout() {
  console.log("Logging out user") // Debug: Log logout process
  cookies().delete("token")
}
