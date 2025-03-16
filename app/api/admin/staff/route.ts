import { NextResponse } from "next/server"
import { connectToDatabase } from "@/lib/db"
import Staff from "@/lib/models/staff"
import { getUser } from "@/lib/auth"

export async function GET() {
  try {
    // Check authentication
    const user = await getUser()
    console.log(user , "these errros from get user file" )
    if (!user) {
      return NextResponse.json({ success: false, error: "Unauthorized" }, { status: 401 })
    }

    await connectToDatabase()
    const staff = await Staff.find().sort({ name: 1 })

    return NextResponse.json({
      success: true,
      data: JSON.parse(JSON.stringify(staff)),
    })
  } catch (error) {
    console.error("Error fetching staff:", error)
    return NextResponse.json({ success: false, error: "Failed to fetch staff" }, { status: 500 })
  }
}

