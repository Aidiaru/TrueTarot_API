using AutoMapper;
using TrueTarot_API.DTOs.Auth;
using TrueTarot_API.Entities;

namespace TrueTarot_API.Infrastructure.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<User, UserDto>()
                .ForMember(dest => dest.Roles, opt => opt.Ignore()); // Roles will be set manually
        }
    }
}