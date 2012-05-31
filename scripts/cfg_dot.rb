#!/usr/bin/ruby
#
# Create graphviz dot from CFG by edu.umd.cs.findbugs.ba.DataflowCFGPrinter
#
# Igor Konnov, 2008

if ARGV.size < 2
    puts "Use: cfg_dot.rb <in_cfg> <out_dot>"
    exit 1
end

cfg_name = ARGV[0]
dot_name = ARGV[1]

File.open(dot_name, "w+") do |outfile|
    outfile.puts("digraph cfg {")
    File.open(cfg_name, "r") do |infile|
        state = "OUT"
        block_num = -1
        edges = []
        handlers = {}

        line_handler = proc do |line|
            case
                when (state == "OUT" and line =~ /^BASIC BLOCK: ([0-9]+)/) then
                    block_num = $1.to_i()
                    state = "BLOCK"
                    label = block_num.to_s()
                    if handlers[block_num] != nil
                        handlers[block_num].each { |from| label += " !#{from}" }
                    end
                    
                    outfile.puts("  b#{block_num}[label=\"#{label}\"];")

                when state == "BLOCK" then
                    state = "EDGES" if line =~ /^END/

                when (state == "EDGES" \
                        and line =~ /(\w+)_EDGE\(\d+\) type (\w+) from block (\d+) to block (\d+)/) then
                    from, to, type = $3.to_i(), $4.to_i(), $2
                    edges.push([from, to, type])

                else
                    if edges.size > 0
                        if edges.size > 3
                            # create special labels for exception handler
                            first = true
                            edges.each do |from, to, type|
                                if type == "HANDLED_EXCEPTION"
                                    handlers[to] = [] if handlers[to] == nil
                                    handlers[to].push(from)
                                    if first
                                        outfile.puts("  b#{from} -> b#{to}"\
                                                     "[label=\"EH1\"];")
                                        first = false
                                    end
                                else
                                    outfile.puts("  b#{from} -> b#{to}"\
                                                 "[label=\"#{type}\"];")
                                end
                            end
                        else
                            edges.each do |from, to, type|
                                label = if type == "FALL_THROUGH"
                                    then ""
                                    else type end
                                outfile.puts("  b#{from} -> b#{to}"\
                                             "[label=\"#{label}\"];")
                            end
                        end
                        edges = []
                    end

                    state = "OUT"
            end # case
        end # line_handler
        infile.each_line { |line| line_handler.call(line) }
        line_handler.call("\n")
    end # open infile
    outfile.puts("}")
end # open outfile
