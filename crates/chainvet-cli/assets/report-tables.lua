-- ChainVet pandoc filter: give every table explicit, content-proportional
-- column widths. Pandoc's LaTeX writer only emits wrapping `p{}` columns when a
-- table carries width info; pipe tables don't, so long unbreakable tokens (file
-- paths) overflow the column. Sizing each column to its widest cell — as a
-- fraction of the text width — turns them into `p{}` columns that wrap, which
-- together with the template's breakable inline code fixes the overflow for any
-- length. PDF-only, so the Markdown/HTML tables stay plain pipe tables.

-- Monospace glyphs (inline code) are wider than proportional text, so a column
-- of code needs more width than its character count implies; nudge it up.
local CODE_WIDTH_FACTOR = 1.6

local function has_code(cell)
  local found = false
  for _, blk in ipairs(cell.contents) do
    pandoc.walk_block(blk, {
      Code = function(_)
        found = true
      end,
    })
  end
  return found
end

local function scan(rows, maxlen, code)
  for _, row in ipairs(rows) do
    for i, cell in ipairs(row.cells) do
      local len = #pandoc.utils.stringify(cell)
      if maxlen[i] == nil or len > maxlen[i] then
        maxlen[i] = len
      end
      code[i] = code[i] or has_code(cell)
    end
  end
end

function Table(t)
  local ncol = #t.colspecs
  if ncol == 0 then
    return nil
  end
  local maxlen, code = {}, {}
  scan(t.head.rows, maxlen, code)
  for _, body in ipairs(t.bodies) do
    scan(body.body, maxlen, code)
  end
  local weight, total = {}, 0
  for i = 1, ncol do
    weight[i] = math.max(maxlen[i] or 1, 1) * (code[i] and CODE_WIDTH_FACTOR or 1.0)
    total = total + weight[i]
  end
  for i = 1, ncol do
    -- keep the column's alignment, set width as a fraction of the text block
    t.colspecs[i] = { t.colspecs[i][1], weight[i] / total }
  end
  return t
end
