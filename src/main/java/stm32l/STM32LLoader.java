/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package stm32l;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class STM32LLoader extends AbstractLibrarySupportLoader {


	private static final STM32MemRegion[] STM32MEM_STM32L1 = { 
			new STM32MemRegion("SPI1", 0x40013000, 0x3FF, true, true, false),
			new STM32MemRegion("SPI2/I2S2", 0x40003800, 0x3FF, true, true, false),
			new STM32MemRegion("SPI3/I2S3", 0x40003C00, 0x3FF, true, true, false),
			new STM32MemRegion("USART1", 0x40013800, 0x3FF, true, true, false),
			new STM32MemRegion("USART2", 0x40004400, 0x3FF, true, true, false),
			new STM32MemRegion("USART3", 0x40004800, 0x3FF, true, true, false),
			new STM32MemRegion("USART4", 0x40004C00, 0x3FF, true, true, false),
			new STM32MemRegion("USART5", 0x40005000, 0x3FF, true, true, false),
			new STM32MemRegion("I2C1", 0x40005400, 0x3FF, true, true, false),
			new STM32MemRegion("I2C2", 0x40005800, 0x3FF, true, true, false),
			new STM32MemRegion("PWR", 0x40007000, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOA", 0x40020000, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOB", 0x40020400, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOC", 0x40020800, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOD", 0x40020c00, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOE", 0x40021000, 0x3FF, true, true, false),
			new STM32MemRegion("GPIOH", 0x40021400, 0x3FF, true, true, false),
			new STM32MemRegion("CRC", 0x40023000, 0x3FF, true, true, false),
			new STM32MemRegion("RCC", 0x40023800, 0x3FF, true, true, false),
			new STM32MemRegion("SRAM", 0x20000000, 0x20000, true, true, true),
			new STM32MemRegion("System Memory", 0x1FF00000, 0x2000, true, true, true),

			// TODO: Add the ability to select and load these in from the loader...
			new STM32MemRegion("Option Bytes", 0x1FF80000, 0x20, true, false, false), };
	
	

	
	private static final STM32MemRegion [] STM32MEM_STM32F = {
			new STM32MemRegion("TIM2",0x40000000,0x3FF,true,true,false),
			new STM32MemRegion("TIM3",0x40000400,0x3FF,true,true,false),
			new STM32MemRegion("TIM4",0x40000800,0x3FF,true,true,false),
			new STM32MemRegion("TIM5",0x40000C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM6",0x40001000,0x3FF,true,true,false),
			new STM32MemRegion("TIM7",0x40001400,0x3FF,true,true,false),
			new STM32MemRegion("TIM12",0x40001800,0x3FF,true,true,false),
			new STM32MemRegion("TIM13",0x40001C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM14",0x40002000,0x3FF,true,true,false),
			new STM32MemRegion("RTC/BKP",0x40002800,0x3FF,true,true,false),
			new STM32MemRegion("WWDG",0x40002C00,0x3FF,true,true,false),
			new STM32MemRegion("IWDG",0x40003000,0x3FF,true,true,false),
			new STM32MemRegion("SPI2/I2S2",0x40003800,0x3FF,true,true,false),
			new STM32MemRegion("SPI3/I2S3",0x40003C00,0x3FF,true,true,false),
			new STM32MemRegion("USART2",0x40004400,0x3FF,true,true,false),
			new STM32MemRegion("USART3",0x40004800,0x3FF,true,true,false),
			new STM32MemRegion("USART4",0x40004C00,0x3FF,true,true,false),
			new STM32MemRegion("USART5",0x40005000,0x3FF,true,true,false),
			new STM32MemRegion("I2C1",0x40005400,0x3FF,true,true,false),
			new STM32MemRegion("I2C2",0x40005800,0x3FF,true,true,false),
			new STM32MemRegion("I2C3",0x40005C00,0x3FF,true,true,false),
			new STM32MemRegion("CAN1",0x40006400,0x3FF,true,true,false),
			new STM32MemRegion("CAN2",0x40006800,0x3FF,true,true,false),
			new STM32MemRegion("PWR",0x40007000,0x3FF,true,true,false),
			new STM32MemRegion("DAC",0x40007400,0x3FF,true,true,false),
			new STM32MemRegion("TIM1",0x40010000,0x3FF,true,true,false),
			new STM32MemRegion("TIM8",0x40010400,0x3FF,true,true,false),
			new STM32MemRegion("USART1",0x40011000,0x3FF,true,true,false),
			new STM32MemRegion("USART6",0x40011400,0x3FF,true,true,false),
			new STM32MemRegion("ADC1/2/3",0x40012000,0x3FF,true,true,false),
			new STM32MemRegion("SDIO",0x40012C00,0x3FF,true,true,false),
			new STM32MemRegion("SPI1",0x40013000,0x3FF,true,true,false),
			new STM32MemRegion("SYSCFG",0x40013800,0x3FF,true,true,false),
			new STM32MemRegion("EXTI",0x40013C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM9",0x40014000,0x3FF,true,true,false),
			new STM32MemRegion("TIM10",0x40014400,0x3FF,true,true,false),
			new STM32MemRegion("TIM11",0x40014800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOA",0x40020000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOB",0x40020400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOC",0x40020800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOD",0x40020c00,0x3FF,true,true,false),
			new STM32MemRegion("GPIOE",0x40021000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOF",0x40021400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOG",0x40021800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOH",0x40021c00,0x3FF,true,true,false),
			new STM32MemRegion("GPIOI",0x40022000,0x3FF,true,true,false),
			new STM32MemRegion("CRC",0x40023000,0x3FF,true,true,false),
			new STM32MemRegion("RCC",0x40023800,0x3FF,true,true,false),
			new STM32MemRegion("Flash Interface Register",0x40023C00,0x3FF,true,true,false),
			new STM32MemRegion("BKPSRAM",0x40024000,0x3FF,true,true,false),
			new STM32MemRegion("DMA1",0x40026000,0x3FF,true,true,false),
			new STM32MemRegion("DMA2",0x40026400 ,0x3FF,true,true,false),
			new STM32MemRegion("Ethernet Mac",0x40028000 ,0x13FF,true,true,false),
			new STM32MemRegion("USB OTG HS",0x40040000 ,0x3FFFF,true,true,false),
			new STM32MemRegion("USB OTG FS",0x50000000 ,0x3FFFF,true,true,false),
			new STM32MemRegion("DCMI",0x50050000 ,0x3FF,true,true,false),
			new STM32MemRegion("CRYP",0x50060000 ,0x3FF,true,true,false),
			new STM32MemRegion("HASH",0x50060400 ,0x3FF,true,true,false),
			new STM32MemRegion("RNG",0x50060800 ,0x3FF,true,true,false),
			new STM32MemRegion("FSMC Control Register",0xA0000000 ,0xFFF,true,true,false),
			new STM32MemRegion("SRAM",0x20000000 ,0x20000,true,true,true),
			new STM32MemRegion("System Memory",0x1FFF0000 ,0x77FF,true,true,true),
			// TODO: Add the ability to select and load these in from the loader...
			new STM32MemRegion("OTP",0x1FFF7800 ,0x20F,true,false,false),
			new STM32MemRegion("Option Bytes",0x1FFFC000 ,0xF,true,false,false),
	};
	
	
	private static final STM32MemRegion [] STM32MEM_STM32L4 = {
			new STM32MemRegion("TIM2",0x40000000,0x3FF,true,true,false),
			new STM32MemRegion("TIM3",0x40000400,0x3FF,true,true,false),
			new STM32MemRegion("TIM4",0x40000800,0x3FF,true,true,false),
			new STM32MemRegion("TIM5",0x40000C00,0x3FF,true,true,false),
			new STM32MemRegion("TIM6",0x40001000,0x3FF,true,true,false),
			new STM32MemRegion("TIM7",0x40001400,0x3FF,true,true,false),
			new STM32MemRegion("RTC/BKP",0x40002800,0x3FF,true,true,false),
			new STM32MemRegion("WWDG",0x40002C00,0x3FF,true,true,false),
			new STM32MemRegion("IWDG",0x40003000,0x3FF,true,true,false),
			new STM32MemRegion("SPI2/I2S2",0x40003800,0x3FF,true,true,false),
			new STM32MemRegion("SPI3/I2S3",0x40003C00,0x3FF,true,true,false),
			new STM32MemRegion("USART2",0x40004400,0x3FF,true,true,false),
			new STM32MemRegion("USART3",0x40004800,0x3FF,true,true,false),
			new STM32MemRegion("USART4",0x40004C00,0x3FF,true,true,false),
			new STM32MemRegion("USART5",0x40005000,0x3FF,true,true,false),
			new STM32MemRegion("I2C1",0x40005400,0x3FF,true,true,false),
			new STM32MemRegion("I2C2",0x40005800,0x3FF,true,true,false),
			new STM32MemRegion("I2C3",0x40005C00,0x3FF,true,true,false),
			new STM32MemRegion("CAN1",0x40006400,0x3FF,true,true,false),
			new STM32MemRegion("PWR",0x40007000,0x3FF,true,true,false),
			new STM32MemRegion("DAC",0x40007400,0x3FF,true,true,false),
			new STM32MemRegion("OPAMP",0x40007800,0x3FF,true,true,false),
			new STM32MemRegion("LPTIM1",0x40007C00,0x3FF,true,true,false),
			new STM32MemRegion("LPUART1",0x40008000,0x3FF,true,true,false),
			new STM32MemRegion("SYSCFG",0x40010000,0x3FF,true,true,false),
			new STM32MemRegion("EXTI",0x40010400,0x3FF,true,true,false),
			new STM32MemRegion("FIREWALL",0x40011C00,0x3FF,true,true,false),
			new STM32MemRegion("SPI1",0x40013000,0x3FF,true,true,false),
			new STM32MemRegion("USART1",0x40013800,0x3FF,true,true,false),
			new STM32MemRegion("RCC",0x40021800,0x3FF,true,true,false),
			new STM32MemRegion("Flash Interface Register",0x40022000,0x3FF,true,true,false),
			new STM32MemRegion("CRC",0x40023000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOA",0x48000000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOB",0x48000400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOC",0x48000800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOD",0x48000c00,0x3FF,true,true,false),
			new STM32MemRegion("GPIOE",0x48001000,0x3FF,true,true,false),
			new STM32MemRegion("GPIOF",0x48001400,0x3FF,true,true,false),
			new STM32MemRegion("GPIOG",0x48001800,0x3FF,true,true,false),
			new STM32MemRegion("GPIOH",0x48001c00,0x3FF,true,true,false),
			new STM32MemRegion("USB OTG FS",0x50000000 ,0x3FFFF,true,true,false),
			new STM32MemRegion("SRAM",0x20000000 ,0x20000,true,true,true),
			new STM32MemRegion("System Memory",0x1FFF0000 ,0x7000,true,true,true),
			// TODO: Add the ability to select and load these in from the loader...
			new STM32MemRegion("OTP",0x1FFF7000 ,0x400,true,false,false),
			new STM32MemRegion("Option Bytes",0x1FFF8000 ,0xF,true,false,false),
	};


	
	private String processorSeries="STM32L1"; //default
	private static STM32MemRegion[] STM32MEM =STM32MEM_STM32L4;
	
	@Override
	public String getName() {

		// TODO: Name the loader. This name must match the name of the loader in the
		// .opinion
		// files.

		return "STM32L1|STM32F| STM32L4";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		// TODO: Examine the bytes in 'provider' to determine if this loader can load
		// it. If it
		// can load it, return the appropriate load specifications.
		BinaryReader reader = new BinaryReader(provider, true);
		byte ram = reader.readByte(4);
		byte flash = reader.readByte(7);
		// controllo se i primi puntano alla ram
		if (ram == 109 && flash == 8) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:Cortex", "default"), true));
			return loadSpecs;
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
		// TODO: Load the bytes from 'provider' into the 'program'.
		getProcessoreType();
			
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		InputStream inStream = provider.getInputStream(0);
		Memory mem = program.getMemory();

		monitor.setMessage("Loading STM32L into memory");

		try {

			for (STM32MemRegion memregion : STM32MEM) {
				mem.createUninitializedBlock(memregion.name.replace(" ", "_"), api.toAddr(memregion.addr), memregion.size, false);
				api.createLabel(api.toAddr(memregion.addr), memregion.name.replace(" ", "_"), false);
			}

			mem.createInitializedBlock("Flash_Memory", api.toAddr(0x8000000), inStream, 0xFFFFF, monitor, false);
			
			int entryPoint = mem.getInt(api.toAddr(0x8000004));
			Data entryPointData = api.createDWord(api.toAddr(0x8000004));
			api.createDWord(api.toAddr(0x8000004));
			api.createLabel(api.toAddr(entryPoint),"_ENTRY_POINT",true);
			api.createMemoryReference(entryPointData, api.toAddr(entryPoint), ghidra.program.model.symbol.RefType.DATA);
	
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Processor Series, stm32l4,stm32f,stm32l1", "")); 

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

				

		return super.validateOptions(provider, loadSpec, options, program);
	}
	
	public String getProcessoreType() {
		if(processorSeries.contains("STM32L4") || processorSeries.contains("stm32l4")){
			this.STM32MEM=this.STM32MEM_STM32L4;
			processorSeries= "STM32L4";
		}
		if(processorSeries.contains("STM32L1") || processorSeries.contains("stm32l1")){
			this.STM32MEM=this.STM32MEM_STM32L1;

			processorSeries= "STM32L1";
		}
		if(processorSeries.contains("STM32F") || processorSeries.contains("stm32F")){
			this.STM32MEM=this.STM32MEM_STM32F;

			processorSeries= "STM32F";
		}
		System.out.println("Choose : "+processorSeries);
			
		return processorSeries;
		
	}
	
	

	private static class STM32MemRegion {
		String name;
		int addr;
		int size;
		boolean read;
		boolean write;
		boolean execute;

		private STM32MemRegion(String name, int addr, int size, boolean read, boolean write, boolean execute) {
			this.name = name;
			this.addr = addr;
			this.size = size;
			this.read = read;
			this.write = write;
			this.execute = execute;
		}
	}

}
