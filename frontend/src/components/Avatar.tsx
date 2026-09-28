"use client";

import { useState } from "react";

function initials(firstName: string, lastName: string): string {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
}

/** The generated avatar shown for a user - seeded by id so it's stable
 * across sessions without needing any avatar-upload storage. Falls back to
 * initials if the avatar service doesn't load. Shared by the sidebar and
 * the Profile page so both always show the same picture. */
export function Avatar({
  userId,
  firstName,
  lastName,
  size,
}: {
  userId: string;
  firstName: string;
  lastName: string;
  size?: number;
}) {
  const [failed, setFailed] = useState(false);
  const style = size ? { width: size, height: size, fontSize: size / 2.6 } : undefined;

  if (failed) {
    return (
      <div className="sidebar-avatar" style={style}>
        {initials(firstName, lastName)}
      </div>
    );
  }

  return (
    <div className="sidebar-avatar" style={style}>
      <img
        src={`https://api.dicebear.com/9.x/avataaars/svg?seed=${encodeURIComponent(userId)}`}
        alt=""
        aria-hidden="true"
        onError={() => setFailed(true)}
      />
    </div>
  );
}
