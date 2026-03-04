use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::{error::Error, io, time::{Duration, Instant}};

struct App {
    logs: Vec<String>,
    memory_map: Vec<u64>,
    stats: Stats,
}

struct Stats {
    block_count: u64,
    stack_depth: u32,
    run_time: Duration,
    mem_writes: u64,
    mem_reads: u64,
    threads: u32,
}

fn main() -> Result<(), Box<dyn Error>> {
    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App {
        logs: vec!["[SYSTEM] Zorya-Volos initialized...".into()],
        memory_map: vec![0; 40],
        stats: Stats {
            block_count: 0,
            stack_depth: 12,
            run_time: Duration::default(),
            mem_writes: 0,
            mem_reads: 0,
            threads: 1,
        },
    };

    let start_time = Instant::now();
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    break;
                }
            }
        }

   


			if last_tick.elapsed() >= tick_rate {
			    // Simulate Data Updates
			    app.stats.block_count += 15;
			    app.stats.mem_reads += 1024;
			    app.stats.run_time = start_time.elapsed();
			    
			    // FIX: Generate a u32 and cast to usize for the index
			    let random_val: u32 = rand::random();
			    let idx = (random_val as usize) % app.memory_map.len();
			    
			    app.memory_map[idx] += 1;
			    
			    if app.stats.block_count % 100 == 0 {
			        // FIX: Use u32 for the address generation here too
			        let addr: u32 = rand::random();
			        app.logs.push(format!("[EVENT] Hooked block at 0x{:08X}", addr));
			    }
			    
			    last_tick = Instant::now();
			}




    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    Ok(())
}

fn ui(f: &mut Frame, app: &App) {
    // 1. Define Main Chunks (Vertical split: Top stuff / Bottom Log)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(f.size());

    // 2. Split Top Chunk (Horizontal split: Stats / Heatmap)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(66), Constraint::Percentage(34)])
        .split(chunks[0]);

    // --- PANE 1: General Stats ---
    let stats_text = format!(
        "Block Count:    {}\nStack Depth:    {}\nRun Time:      {:?}\nMem Writes:     {}\nMem Reads:      {}\nThreads:        {}",
        app.stats.block_count, app.stats.stack_depth, app.stats.run_time,
        app.stats.mem_writes, app.stats.mem_reads, app.stats.threads
    );
    let stats_block = Paragraph::new(stats_text)
        .block(Block::default().title(" EXECUTION STATS ").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(stats_block, top_chunks[0]);

    // --- PANE 2: Memory Heatmap (Right) ---
    let heatmap_items: Vec<ListItem> = app.memory_map.iter().enumerate().map(|(i, &hits)| {
        let addr = i as u64 * (0xFFFFFFFF / app.memory_map.len() as u64);
        let color = match hits {
            0 => Color::DarkGray,
            1..=5 => Color::Blue,
            6..=15 => Color::Yellow,
            _ => Color::Red,
        };
        ListItem::new(format!("0x{:08X} [█]", addr)).style(Style::default().fg(color))
    }).collect();

    let heatmap = List::new(heatmap_items)
        .block(Block::default().title(" MEM MAP ").borders(Borders::ALL));
    f.render_widget(heatmap, top_chunks[1]);

    // --- PANE 3: Scrolling Log (Bottom) ---
    // We take the last N logs that fit the height
    let log_height = chunks[1].height as usize;
    let display_logs: Vec<ListItem> = app.logs.iter().rev().take(log_height)
        .map(|s| ListItem::new(s.as_str())).collect();
    
    let log_list = List::new(display_logs)
        .block(Block::default().title(" LOG OUTPUT (Q to quit) ").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));
    f.render_widget(log_list, chunks[1]);
}
