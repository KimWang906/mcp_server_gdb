use std::sync::atomic::Ordering;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::prelude::Stylize;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use super::{GREEN, ORANGE, PURPLE};
use crate::App;

pub fn draw_asm<'a>(app: &mut App, f: &mut Frame<'a>, asm: Rect) {
    // Asm
    let mut rows = vec![];
    let app_cur = app.current_pc.load(Ordering::Relaxed);
    let cache_valid = app.asm_cache.len == app.asm.len()
        && app.asm_cache.pc == app_cur
        && app.asm_cache.pc_index.map_or(true, |idx| {
            app.asm.get(idx).map_or(false, |a| a.address == app_cur)
        });
    let mut pc_index = if cache_valid { app.asm_cache.pc_index } else { None };
    let mut function_name = if cache_valid {
        app.asm_cache.function_name.clone()
    } else {
        None
    };
    let mut tallest_function_len =
        if cache_valid { app.asm_cache.tallest_function_len } else { 0 };

    // Display asm, this will already be in a sorted order
    for (index, a) in app.asm.iter().enumerate() {
        if !cache_valid && a.address == app_cur {
            pc_index = Some(index);
            if let Some(func_name) = &a.func_name {
                function_name = Some(func_name.clone());
                tallest_function_len = func_name.len();
            }
        }
        let addr_cell =
            Cell::from(format!("0x{:02x}", a.address)).style(Style::default().fg(PURPLE));
        let mut row = vec![addr_cell];

        if let Some(function_name) = &a.func_name {
            let function_cell = Cell::from(format!("{}+{:02x}", function_name, a.offset))
                .style(Style::default().fg(PURPLE));
            row.push(function_cell);
        } else {
            row.push(Cell::from(""));
        }

        let inst_cell = if let Some(pc_index) = pc_index {
            if pc_index == index {
                Cell::from(a.inst.to_string()).fg(GREEN)
            } else {
                Cell::from(a.inst.to_string()).white()
            }
        } else {
            Cell::from(a.inst.to_string()).dark_gray()
        };
        row.push(inst_cell);

        rows.push(Row::new(row));
    }

    if !cache_valid {
        app.asm_cache.pc = app_cur;
        app.asm_cache.len = app.asm.len();
        app.asm_cache.pc_index = pc_index;
        app.asm_cache.function_name = function_name.clone();
        app.asm_cache.tallest_function_len = tallest_function_len;
    }

    let tital = if let Some(function_name) = function_name {
        Line::from(format!("Instructions ({})", function_name)).fg(ORANGE)
    } else {
        Line::from("Instructions").fg(ORANGE)
    };
    if let Some(pc_index) = pc_index {
        let widths = [
            Constraint::Length(16),
            Constraint::Length(tallest_function_len as u16 + 5),
            Constraint::Fill(1),
        ];
        let table = Table::new(rows, widths)
            .block(Block::default().borders(Borders::TOP).title(tital))
            .row_highlight_style(Style::new().fg(GREEN))
            .highlight_symbol(">>");
        let start_offset = if pc_index < 5 { 0 } else { pc_index - 5 };
        let mut table_state =
            TableState::default().with_offset(start_offset).with_selected(pc_index);
        f.render_stateful_widget(table, asm, &mut table_state);
    } else {
        let block = Block::default().borders(Borders::TOP).title(tital);
        f.render_widget(block, asm);
    }
}
