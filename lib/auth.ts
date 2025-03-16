"use server"

import { cookies } from "next/headers"
import { SignJWT, jwtVerify } from "jose"
import { redirect } from "next/navigation"
import bcrypt from "bcryptjs"
import { v4 as uuidv4 } from "uuid"
import { ensureServerOnly } from "./server-only"

// Ensure this code only runs on the server
ensureServerOnly()
console.log("Server-only check passed")

import User from "@/lib/models/user"
import { connectToDatabase } from "@/lib/db"

// Environment variables
const JWT_SECRET = "hbjgvgjvgjhbvvutyrcf"
console.log("JWT_SECRET loaded:", JWT_SECRET)

if (!JWT_SECRET) {
  console.log("JWT secret key is not found // this is from auth.js page")
  throw new Error("JWT_SECRET environment variable is not defined")
}

// Create a JWT token
export async function createToken(payload) {
  console.log("Creating JWT token for payload:", payload)
  const jti = uuidv4()
  console.log("Generated JTI:", jti)

  const token = await new SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(new TextEncoder().encode(JWT_SECRET))

  console.log("Token created successfully")
  return token
}

// Verify a JWT token
export async function verifyToken(token) {
  try {
    console.log("Verifying token:", token)
    const { payload } = await jwtVerify(token, new TextEncoder().encode(JWT_SECRET), {
      clockTolerance: 15,
    })
    console.log("Token verified successfully:", payload)
    return payload
  } catch (error) {
    console.error("Token verification error:", error)
    return null
  }
}

// Set a JWT token in cookies
export async function setTokenCookie(token) {
  console.log("Setting token cookie:", token)
  cookies().set({
    name: "token",
    value: token,
    httpOnly: true,
    path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 8, // 8 hours
    sameSite: "strict",
  })
  console.log("Token cookie set successfully")
}

// Get the current user from the token
export async function getCurrentUser() {
  try {
    console.log("Fetching current user")
    const token = cookies().get("token")?.value
    console.log("Token from cookies:", token)

    if (!token) {
      console.log("No token found, returning null")
      return null
    }

    const payload = await verifyToken(token)
    console.log("Payload from token:", payload)

    if (!payload || !payload.id) {
      console.log("Invalid payload, returning null")
      return null
    }

    await connectToDatabase()
    console.log("Database connected")

    const user = await User.findById(payload.id).select("-password")
    console.log("User found:", user)

    if (!user) {
      console.log("User not found in DB, returning null")
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
  try {
    console.log("Fetching user from request")
    const token = cookies().get("token")?.value
    console.log("Token from getUser:", token)

    if (!token) {
      console.log("No token found, returning null")
      return null
    }

    const payload = await verifyToken(token)
    console.log("Payload from verifyToken:", payload)

    if (!payload || !payload.id) {
      console.log("Invalid payload, returning null")
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
export async function requireAuth(requiredRole) {
  console.log("Checking authentication")
  const user = await getCurrentUser()
  console.log("Current user:", user)

  if (!user) {
    console.log("User not authenticated, redirecting to login")
    redirect("/admin/login")
  }

  if (requiredRole && user.role !== requiredRole) {
    console.log("User role mismatch, required:", requiredRole, "but found:", user.role)
    if (requiredRole === "admin" && user.role === "staff") {
      console.log("Redirecting staff to /admin")
      redirect("/admin")
    }
  }

  return user
}

// Hash a password
export async function hashPassword(password) {
  console.log("Hashing password")
  return bcrypt.hash(password, 12)
}

// Compare a password with a hash
export async function comparePassword(password, hash) {
  console.log("Comparing password")
  return bcrypt.compare(password, hash)
}

// Logout the user
export async function logout() {
  console.log("Logging out user, deleting token cookie")
  cookies().delete("token")
}
