"use server"

import { revalidatePath } from "next/cache"
import { connectToDatabase } from "@/lib/db"
import User from "@/lib/models/user"
import { requireAuth, hashPassword } from "@/lib/auth"

// Get all admin users
export async function getAdminUsers() {
  console.log("Fetching admin users")
  const user = await requireAuth()
  console.log("Authenticated user:", user)

  if (user.role !== "admin") {
    console.log("Unauthorized access attempt")
    return { success: false, error: "Unauthorized" }
  }

  await connectToDatabase()
  console.log("Database connected")

  try {
    const users = await User.find().select("username role createdAt updatedAt").sort({ createdAt: -1 })
    console.log("Fetched users:", users)
    return { success: true, data: JSON.parse(JSON.stringify(users)) }
  } catch (error) {
    console.error("Error fetching admin users:", error)
    return { success: false, error: "Failed to fetch admin users" }
  }
}

// Create a new admin user
export async function createAdminUser(formData) {
  console.log("Creating new admin user")
  const currentUser = await requireAuth()
  console.log("Authenticated user:", currentUser)

  if (currentUser.role !== "admin") {
    console.log("Unauthorized user creation attempt")
    return { success: false, error: "Unauthorized" }
  }

  await connectToDatabase()
  console.log("Database connected")

  try {
    const username = formData.get("username")
    const password = formData.get("password")
    const role = formData.get("role")

    console.log("Checking if username exists:", username)
    const existingUser = await User.findOne({ username })
    if (existingUser) {
      console.log("Username already exists")
      return { success: false, error: "Username already exists" }
    }

    const hashedPassword = await hashPassword(password)
    console.log("Password hashed successfully")

    await User.create({ username, password: hashedPassword, role })
    console.log("User created successfully")

    revalidatePath("/admin/users")
    return { success: true }
  } catch (error) {
    console.error("Error creating admin user:", error)
    return { success: false, error: "Failed to create admin user" }
  }
}

// Update an admin user
export async function updateAdminUser(id, formData) {
  console.log("Updating admin user with ID:", id)
  const currentUser = await requireAuth()
  console.log("Authenticated user:", currentUser)

  if (currentUser.role !== "admin") {
    console.log("Unauthorized user update attempt")
    return { success: false, error: "Unauthorized" }
  }

  await connectToDatabase()
  console.log("Database connected")

  try {
    const username = formData.get("username")
    const password = formData.get("password")
    const role = formData.get("role")

    console.log("Checking if username exists excluding current user")
    const existingUser = await User.findOne({ username, _id: { $ne: id } })
    if (existingUser) {
      console.log("Username already exists")
      return { success: false, error: "Username already exists" }
    }

    const updateData = { username, role }
    if (password) {
      updateData.password = await hashPassword(password)
      console.log("Password updated successfully")
    }

    await User.findByIdAndUpdate(id, updateData)
    console.log("User updated successfully")

    revalidatePath("/admin/users")
    return { success: true }
  } catch (error) {
    console.error("Error updating admin user:", error)
    return { success: false, error: "Failed to update admin user" }
  }
}

// Delete an admin user
export async function deleteAdminUser(id) {
  console.log("Deleting admin user with ID:", id)
  const currentUser = await requireAuth()
  console.log("Authenticated user:", currentUser)

  if (currentUser.role !== "admin") {
    console.log("Unauthorized user deletion attempt")
    return { success: false, error: "Unauthorized" }
  }

  await connectToDatabase()
  console.log("Database connected")

  try {
    const userCount = await User.countDocuments({ role: "admin" })
    console.log("Admin user count:", userCount)

    if (userCount <= 1) {
      const user = await User.findById(id)
      if (user && user.role === "admin") {
        console.log("Cannot delete the last admin user")
        return { success: false, error: "Cannot delete the last admin user" }
      }
    }

    if (id === currentUser.id) {
      console.log("User attempted to delete themselves")
      return { success: false, error: "You cannot delete your own account" }
    }

    await User.findByIdAndDelete(id)
    console.log("User deleted successfully")

    revalidatePath("/admin/users")
    return { success: true }
  } catch (error) {
    console.error("Error deleting admin user:", error)
    return { success: false, error: "Failed to delete admin user" }
  }
}

// Get a single admin user
export async function getAdminUser(id) {
  console.log("Fetching admin user with ID:", id)
  const currentUser = await requireAuth()
  console.log("Authenticated user:", currentUser)

  if (currentUser.role !== "admin") {
    console.log("Unauthorized access to user details")
    return { success: false, error: "Unauthorized" }
  }

  await connectToDatabase()
  console.log("Database connected")

  try {
    const user = await User.findById(id).select("username role")
    if (!user) {
      console.log("User not found")
      return { success: false, error: "User not found" }
    }
    console.log("User details fetched successfully:", user)
    return { success: true, data: JSON.parse(JSON.stringify(user)) }
  } catch (error) {
    console.error("Error fetching admin user:", error)
    return { success: false, error: "Failed to fetch admin user" }
  }
}
