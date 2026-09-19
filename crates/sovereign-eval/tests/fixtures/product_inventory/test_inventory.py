from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server import InventoryStore, render_page, render_read_only_page  # noqa: E402


class InventoryTests(unittest.TestCase):
    def test_crud_search_validation_and_ui_contract(self) -> None:
        store = InventoryStore(":memory:")
        try:
            with self.assertRaisesRegex(ValueError, "name_required"):
                store.create("", "0")
            item_id = store.create("Widget", "3")
            self.assertEqual([row["name"] for row in store.search("Wid")], ["Widget"])
            store.update(item_id, "Widget Pro", "5")
            row = store.search("Pro")[0]
            self.assertEqual((row["name"], row["quantity"]), ("Widget Pro", 5))
            page = render_page(ROOT, store, "Pro").decode("utf-8")
            self.assertIn('id="create-widget"', page)
            self.assertIn(f'id="edit-{item_id}"', page)
            self.assertIn(f'id="delete-{item_id}"', page)
            self.assertIn("Widget Pro", page)
            view = render_read_only_page(store, "Pro").decode("utf-8")
            self.assertIn("Widget Pro", view)
            self.assertIn("quantity=5", view)
            self.assertNotIn("<form", view)
            self.assertNotIn("<input", view)
            store.delete(item_id)
            self.assertEqual(store.search(""), [])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
