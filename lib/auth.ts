"use server"

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
console.log(JWT_SECRET)

if (!JWT_SECRET) {
  console.log("jwt secret key is not found // this is from auth.js page")
  throw new Error("JWT_SECRET environment variable is not defined")
}

// Create a JWT token
export async function createToken(payload: any) {
  const jti = uuidv4() // Unique JWT ID to prevent token reuse

  const token = await new SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h") // 8-hour expiration time
    .sign(new TextEncoder().encode(JWT_SECRET))

  console.log(`Created token for user: ${payload.id}, expiration: 8h`)
  return token
}

// Verify a JWT token
export async function verifyToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(JWT_SECRET), {
      clockTolerance: 15, // Allow clock skew of 15 seconds
    })
    console.log(`Token verified successfully: ${payload.id}`)
    return payload
  } catch (error) {
    console.error("Token verification error:", error)
    return null
  }
}

// Set a JWT token in cookies
export async function setTokenCookie(token: string) {
  cookies().set({
    name: "token",
    value: token,
    httpOnly: true, // Can't be accessed via JavaScript
    path: "/",
    secure: process.env.NODE_ENV === "production", // Set to true for HTTPS (Vercel uses HTTPS)
    maxAge: 60 * 60 * 8, // 8 hours
    sameSite: process.env.NODE_ENV === "production" ? "Lax" : "Strict", // Adjusted SameSite for production vs. dev
  })

  console.log("Token cookie set successfully.")
}

// Get the current user from the token
export async function getCurrentUser() {
  try {
    const token = cookies().get("token")?.value
    if (!token) {
      console.log("No token found.")
      return null
    }

    const payload = await verifyToken(token)
    if (!payload || !payload.id) {
      console.log("Invalid token payload.")
      return null
    }

    await connectToDatabase()
    const user = await User.findById(payload.id).select("-password")

    if (!user) {
      console.log("User not found.")
      return null
    }

    console.log(`User found: ${user.username}, role: ${user.role}`)
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
  try {
    const token = cookies().get("token")?.value
    if (!token) {
      console.log("No token found.")
      return null
    }

    const payload = await verifyToken(token)
    if (!payload || !payload.id) {
      console.log("Invalid token payload.")
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
  const user = await getCurrentUser()

  if (!user) {
    console.log("User not authenticated, redirecting to login.")
    redirect("/admin/login")
  }

  // If a specific role is required, check if the user has that role
  if (requiredRole && user.role !== requiredRole) {
    console.log(`User role mismatch. Required: ${requiredRole}, user role: ${user.role}`)
    // If admin role is required but user is staff, redirect to dashboard
    if (requiredRole === "admin" && user.role === "staff") {
      redirect("/admin")
    }
  }

  console.log(`User authenticated: ${user.username}, role: ${user.role}`)
  return user
}

// Hash a password
export async function hashPassword(password: string) {
  return bcrypt.hash(password, 12)
}

// Compare a password with a hash
export async function comparePassword(password: string, hash: string) {
  return bcrypt.compare(password, hash)
}

// Logout the user
export async function logout() {
  cookies().delete("token")
  console.log("User logged out. Token cookie deleted.")
  redirect("/admin/login") // Ensure redirect to login after logout
}
