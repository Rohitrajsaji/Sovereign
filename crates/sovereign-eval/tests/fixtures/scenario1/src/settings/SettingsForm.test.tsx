import { render, screen } from "@testing-library/react";
import { SettingsForm } from "./SettingsForm";

test("renders the current submit label", () => {
  render(<SettingsForm />);
  expect(screen.getByRole("button", { name: "Save" })).toBeTruthy();
});
