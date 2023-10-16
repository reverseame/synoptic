import os
import sys
import shlex
import capstone
import subprocess

import synoptic.args
import synoptic.utils as utils
import synoptic.debug as debug
import synoptic.tracemodeler.model
import synoptic.tracemodeler.version
import synoptic.tracemodeler.replayer as replayer

def print_version():
    print(f'{utils.TOOL_NAME}\t\t: {utils.VERSION}')
    print(f'{synoptic.tracemodeler.version.TOOL_NAME}\t: {synoptic.tracemodeler.version.VERSION}')
    (servertracer_name, servertracer_version) = utils.get_servertracer_info()
    print(f'{servertracer_name}\t: {servertracer_version}')

def analyze_logs(args, model, working_dir):
    filenames = utils.get_logs(working_dir)

    """ Proceed with CFG and FSM analysis """
    traces = utils.get_traces(filenames)
    model.analyze(traces)

    """ Symbolic analysis of traces """
    if args.symbolic_analysis:
        model.symbolic_analysis(traces, args.binary, args.binary_args, args.symbolic_engine, args.symbolic_timeout)

    """ Export dynamic CFG """
    if args.export_pdf:
        cfg_pdf = os.path.join(working_dir, 'cfg.pdf')
        if model.cfg.is_empty():
            debug.warning('Empty CFG')
        else:
            model.cfg.export_graph(cfg_pdf)
            debug.info(f'{cfg_pdf}\t: CFG graph exported')

    if model.fsm.is_empty():
        debug.warning('Empty FSM')
    else:
        """ Export FSM for use in next iteration """
        fsm_json = os.path.join(working_dir, 'fsm.json')
        model.fsm.export_to_file(fsm_json)
        debug.info(f'{fsm_json}\t: FSM exported')

        if args.export_pdf:
            fsm_pdf = os.path.join(working_dir, 'fsm.pdf')
            model.fsm.export_graph(fsm_pdf)
            debug.info(f'{fsm_pdf}\t: FSM graph exported')

    return model

def execute_servertracer(args, iteration):
    """ Creates log folder """
    working_dir = os.path.join(args.working_dir, f'iteration-{iteration:#03}')
    os.makedirs(working_dir)

    """ Execute servertracer submodule """
    command = []

    """ pintool knobs """
    if args.binary_privileges:
        command = ['sudo']
    command.extend([args.pin, '-follow_execv', '-t', os.path.abspath(args.pintool)])
    if args.debug:
        command.append('-debug')
    command.extend(['-dirlog', working_dir])
    if args.binary_modules:
        command.append('-modules')
        command.append(args.binary_modules)

    """ binary arguments """
    command.extend(['--', args.binary])
    """ Split string to list """
    command.extend(shlex.split(args.binary_args))

    debug.info(f'Executing servertracer submodule\t: {" ".join(command)}')

    """ At first iteration, waits till binary is finished """
    if iteration == 0:
        completed_process = subprocess.run(command, cwd=args.binary_cwd)
    else:
        import pdb; pdb.set_trace()

    return (completed_process, working_dir)

def main():
    args = synoptic.args.ArgumentParser().parse_args(sys.argv[1:])

    if args.version:
        print_version()
        sys.exit(0)

    if args.binary_bitmode == '32-bit':
        arch_mode = capstone.CS_MODE_32 
    elif args.binary_bitmode == '64-bit':
        arch_mode = capstone.CS_MODE_64

    model = synoptic.tracemodeler.model.Model(arch_mode=arch_mode)

    '''
    iteration = 0
    (completed_process, working_dir) = execute_servertracer(args, iteration=iteration)
    """ Update protocol model with last logs """
    model = analyze_logs(args, model, working_dir)
    iteration += 1
    '''


    try:
        '''
        """
        Execute until user interruption, binary execution error, or max. number of iterations
        reached
        """
        while (completed_process.returncode == 0) and (iteration < args.n_iterations):
            (completed_process, working_dir) = execute_servertracer(args, iteration=iteration)
            if args.replay:
                replayer.Replayer(args.replay_ip, args.replay_port, transport_layer=args.replay_transport_layer).replay(model.fsm, delay=(args.replay_delay / 1000), symbolic_messages=args.replay_symbolic_messages)
            model = analyze_logs(args, model, working_dir)
            iteration += 1
        '''
        if args.replay:
            with open('/home/xubuntu/shared/experiments/proftpd/complex/iteration-000/fsm.json', 'r') as f:
                data = f.read()
            model.fsm.loads(data)
            model.fsm = replayer.Replayer(args.replay_ip, args.replay_port, args.replay_transport_layer, args.replay_delay / 1000).replay(model.fsm, symbolic_messages=args.replay_symbolic_messages)
            
            """ Export inferred FSM """
            fsm_json = os.path.join('/tmp', 'fsm-inferred.json')
            model.fsm.export_to_file(fsm_json)
            debug.info(f'{fsm_json}\t: Inferred FSM exported')

            if args.export_pdf:
                fsm_pdf = os.path.join('/tmp', 'fsm-inferred.pdf')
                model.fsm.export_graph(fsm_pdf)
                debug.info(f'{fsm_pdf}\t: FSM graph exported')
    except KeyboardInterrupt:
        debug.info('User interrupt')
    finally:
        debug.info('Analysis finished')
