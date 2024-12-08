// chartUtils.js
export function drawBarChart(data) {
    console.log('Drawing chart with data:', data);  // Debugging log

    const margin = { top: 20, right: 30, bottom: 40, left: 40 };
    const width = 600 - margin.left - margin.right;
    const height = 400 - margin.top - margin.bottom;

    // Select the chart div and create the SVG container
    const svg = d3.select('#stocks-chart')
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left}, ${margin.top})`);

    // Set up the x and y scales
    const x = d3.scaleBand()
        .domain(data.map(d => d.symbol))
        .range([0, width])
        .padding(0.1);

    const y = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.price)])
        .nice()
        .range([height, 0]);

    // Append the x-axis to the SVG
    svg.append('g')
        .attr('class', 'x-axis')
        .attr('transform', `translate(0, ${height})`)
        .call(d3.axisBottom(x));

    // Append the y-axis to the SVG
    svg.append('g')
        .attr('class', 'y-axis')
        .call(d3.axisLeft(y));

    // Draw bars for each stock
    svg.selectAll('.bar')
        .data(data)
        .enter().append('rect')
        .attr('class', 'bar')
        .attr('x', d => x(d.symbol))
        .attr('y', d => y(d.price))
        .attr('width', x.bandwidth())
        .attr('height', d => height - y(d.price))
        .attr('fill', 'steelblue');

    console.log('Chart drawn successfully');
}
export function drawLineChart(data) {
    console.log('Drawing line chart with data:', data);  // Debugging log

    const margin = { top: 20, right: 30, bottom: 40, left: 40 };
    const width = 600 - margin.left - margin.right;
    const height = 400 - margin.top - margin.bottom;

    const svg = d3.select('#search-results-chart')
        .append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom)
        .append('g')
        .attr('transform', `translate(${margin.left}, ${margin.top})`);

    const parseTime = d3.timeParse("%Y-%m-%d");
    data.forEach(d => {
        d.date = parseTime(d.date);
        d.price = +d.price; // Convert price to number
    });

    const x = d3.scaleTime()
        .domain(d3.extent(data, d => d.date))
        .range([0, width]);

    const y = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.price)])
        .nice()
        .range([height, 0]);

    svg.append('g')
        .attr('class', 'x-axis')
        .attr('transform', `translate(0, ${height})`)
        .call(d3.axisBottom(x));

    svg.append('g')
        .attr('class', 'y-axis')
        .call(d3.axisLeft(y));

    const area = d3.area()
        .x(d => x(d.date))
        .y0(height)
        .y1(d => y(d.price));

    svg.append('path')
        .datum(data)
        .attr('fill', 'lightblue')
        .attr('d', area);

    const line = d3.line()
        .x(d => x(d.date))
        .y(d => y(d.price));

    svg.append('path')
        .datum(data)
        .attr('fill', 'none')
        .attr('stroke', 'steelblue')
        .attr('stroke-width', 2)
        .attr('d', line);

    console.log('Line chart with area drawn successfully');
}


// Function to draw scatter plot the D3 chart with new data
export function drawScatterPlotChart(data) {
    const margin = { top: 20, right: 30, bottom: 40, left: 60 };
    const width = 600 - margin.left - margin.right;
    const height = 400 - margin.top - margin.bottom;

    const svg = d3.select('#stocks-chart svg g');

    const xPadding = (d3.max(data, d => d.change) - d3.min(data, d => d.change)) * 0.1 || 1;
    const yPadding = (d3.max(data, d => d.profit) - d3.min(data, d => d.profit)) * 0.1 || 1;

    const x = d3.scaleLinear()
        .domain([
            Math.min(0, d3.min(data, d => d.change) - xPadding),
            Math.max(0, d3.max(data, d => d.change) + xPadding)
        ])
        .range([0, width]);

    const y = d3.scaleLinear()
        .domain([
            Math.min(0, d3.min(data, d => d.profit) - yPadding),
            Math.max(0, d3.max(data, d => d.profit) + yPadding)
        ])
        .range([height, 0]);

    svg.select('.x-axis')
        .attr('transform', `translate(0,${y(0)})`)
        .transition().duration(750)
        .call(d3.axisBottom(x).tickFormat(d => `${d}%`));

    svg.select('.y-axis')
        .attr('transform', `translate(${x(0)},0)`)
        .transition().duration(750)
        .call(d3.axisLeft(y).tickFormat(d => `$${d.toFixed(2)}`));

    svg.select('.x-axis-label').remove();
    svg.append('text')
        .attr('class', 'x-axis-label')
        .attr('x', width / 2)
        .attr('y', height + margin.bottom - 10)
        .attr('text-anchor', 'middle')
        .text('Change (%)');

    svg.select('.y-axis-label').remove();
    svg.append('text')
        .attr('class', 'y-axis-label')
        .attr('x', -height / 2)
        .attr('y', -margin.left + 15)
        .attr('text-anchor', 'middle')
        .attr('transform', 'rotate(-90)')
        .text('Profit ($)');

    const dots = svg.selectAll('.dot').data(data);

    dots.enter()
        .append('circle')
        .attr('class', 'dot')
        .attr('r', 6)
        .merge(dots)
        .transition().duration(750)
        .attr('cx', d => x(d.change))
        .attr('cy', d => y(d.profit))
        .attr('fill', d => d.profit >= 0 ? 'steelblue' : 'red');

    dots.exit().remove();

    // Add stock names as labels
    const labels = svg.selectAll('.label').data(data);

    labels.enter()
        .append('text')
        .attr('class', 'label')
        .merge(labels)
        .transition().duration(750)
        .attr('x', d => x(d.change) + 8) // Offset label slightly to the right of the dot
        .attr('y', d => y(d.profit))
        .text(d => d.ticker)
        .attr('font-size', '12px')
        .attr('fill', 'black');

    labels.exit().remove();
}



