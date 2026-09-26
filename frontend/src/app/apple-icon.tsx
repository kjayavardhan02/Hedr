import { ImageResponse } from "next/og";

// Home-screen icon for iOS (the SVG tab icon isn't used there).
export const size = { width: 180, height: 180 };
export const contentType = "image/png";

export default function AppleIcon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#161616",
        }}
      >
        <svg width="132" height="132" viewBox="0 0 24 24" fill="none">
          <path
            d="M12 2.5 4.5 5.3v5.4c0 5 3.2 8.8 7.5 10.8 4.3-2 7.5-5.8 7.5-10.8V5.3L12 2.5Z"
            fill="#ff7a1a"
            fillOpacity="0.22"
            stroke="#ff7a1a"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <path d="M8.7 12.1l2.2 2.2 4.4-4.6" stroke="#ff7a1a" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
    ),
    size
  );
}
