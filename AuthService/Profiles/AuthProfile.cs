using AuthService.DTOs;
using AuthService.Models;
using AutoMapper;
using Shared.Enums;

namespace AuthService.Profiles
{
    public class AuthProfile : Profile
    {
        public AuthProfile()
        {
            CreateMap<AppUser, AppUserDto>().ReverseMap();

            CreateMap<AuthLog, AuthLogDto>()
                .ForMember(dest => dest.EventType,
                           opt => opt.MapFrom(src => src.EventType.ToString()));

            CreateMap<AuthLogDto, AuthLog>()
                .ForMember(dest => dest.EventType,
                           opt => opt.MapFrom(src =>
                               Enum.Parse<AuthEventType>(src.EventType)));
        }
    }
}
