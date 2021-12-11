#pragma once
#include "IP6Packet.h"
#include "Packet.h"
bool operator==(const ip6_address addr1, const ip6_address addr2)//is there a better way to do this? Probably, do I know how? Kinda but it didn't work out.
//what this does is check equality across 2 different ip6addresses byte by byte, there is a way to loop structs using pointers in C++, I'm bad at it.
//if only this was JS where that's super easy.
{
	if (addr1.byte1 == addr2.byte1)
	{
		if (addr1.byte2 == addr2.byte2)
		{
			if (addr1.byte3 == addr2.byte3)
			{
				if (addr1.byte4 == addr2.byte4)
				{
					if (addr1.byte5 == addr2.byte5)
					{
						if (addr1.byte6 == addr2.byte6)
						{
							if (addr1.byte7 == addr2.byte7)
							{
								if (addr1.byte8 == addr2.byte8)
								{
									if (addr1.byte9 == addr2.byte9)
									{
										if (addr1.byte10 == addr2.byte10)
										{
											if (addr1.byte11 == addr2.byte11)
											{
												if (addr1.byte12 == addr2.byte12)
												{
													if (addr1.byte13 == addr2.byte13)
													{
														if (addr1.byte14 == addr2.byte14)
														{
															if (addr1.byte15 == addr2.byte15)
															{
																if (addr1.byte16 == addr2.byte16)
																{
																	return true;
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false;
}
bool operator==(const ip_address addr1, const ip_address addr2)//cleaner implementation of the above function done in a single check
{
	if (addr1.byte1 == addr2.byte1 && addr1.byte2 == addr2.byte2 && addr1.byte3 == addr2.byte3 && addr1.byte4 == addr2.byte4)
	{
		return true;
	}
	return false;
}