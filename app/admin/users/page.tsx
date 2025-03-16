import Link from "next/link"
import type { Metadata } from "next"
import { Plus } from "lucide-react"

import { Button } from "@/components/ui/button"
import { UsersTable } from "@/components/admin/users-table"
import { getAdminUsers } from "@/app/actions/users"
import { AdminNav } from "@/components/admin-nav"

export const metadata: Metadata = {
  title: "Users | Admin",
  description: "Manage admin users for Brew Haven Coffee",
}

export default async function UsersPage() {
  console.log("user page")
  const result = await getAdminUsers()
  const users = result.success ? result.data : []
  console.log(users)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">User Management</h1>
        <Button asChild>
          <Link href="/admin/users/new">
            <Plus className="mr-2 h-4 w-4" />
            Add New User
          </Link>
        </Button>
      </div>

      <AdminNav />

      <UsersTable users={users} />
    </div>
  )
}

